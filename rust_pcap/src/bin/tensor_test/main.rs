use std::collections::HashSet;
use std::env;
use std::error::Error;
use pcap_parser::*;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Instant;
use rust_pcap::*;

use tensorflow::{
    ops,
    train::{AdadeltaOptimizer, MinimizeOptions, Optimizer},
    Code,
    DataType,
    Graph,
    Output,
    OutputName,
    SavedModelBundle,
    Scope,
    Session,
    SessionOptions,
    SessionRunArgs,
    Shape,
    SignatureDef,
    Status,
    Tensor,
    TensorInfo,
    Variable,
    REGRESS_INPUTS, REGRESS_METHOD_NAME, REGRESS_OUTPUTS,
};


fn get_stats(file: File) -> [f32; 16] {
    let mut num_blocks = 0usize;
    let mut ip_count = 0;
    let mut tcp_count = 0;
    let mut udp_count = 0;
    let mut icmp_count = 0;
    let mut arp_count = 0;
    let mut http_count = 0;
    let mut dhcp_count = 0;
    let mut addresses = HashSet::new();
    let mut ports = HashSet::new();
    let mut data_bytes = 0;
    let mut pkt_sizes = Vec::new();
    let mut last_time = None;
    let mut pkt_times = Vec::new();
    let mut collect_stats = |frame: Frame| -> bool  {
        num_blocks += 1;
        pkt_sizes.push(frame.data.len());
        if let Some(time) = last_time {
            pkt_times.push(time - frame.ts_sec);
        }
        last_time = Some(frame.ts_sec);
        if let Some(ipv4) = frame.get_layer::<IPv4>() {
            ip_count += 1;
            addresses.insert(ipv4.src);
            addresses.insert(ipv4.dst);
        }
        if let Some(udp) = frame.get_layer::<UDP>() {
            udp_count += 1;
            data_bytes += udp.payload.len();
        }
        if let Some(tcp) = frame.get_layer::<TCP>() {
            tcp_count += 1;
            ports.insert(tcp.src);
            ports.insert(tcp.dst);
            data_bytes += tcp.data.len();
        }
        if let Some(_) = frame.get_layer::<ICMP>() {
            icmp_count += 1;
        }
        if let Some(_) = frame.get_layer::<ARP>() {
            arp_count += 1;
        }
        if let Some(_) = frame.get_layer::<HTTP>() {
            http_count += 1;
        }
        if let Some(_) = frame.get_layer::<DHCP>() {
            dhcp_count += 1;
        }
        false
    };
    // iter_over_pcap(file, collect_stats);
    iter_over_pcapng(file, collect_stats);
    let bytes: usize = pkt_sizes.iter().sum();
    let avg_size = bytes as f32 / num_blocks as f32;
    let avg_deltas_size = pkt_sizes.iter()
        .map(|&s| (avg_size - s as f32).abs())
        .sum::<f32>() / num_blocks as f32;
    let avg_time = pkt_times.iter().sum::<u32>() as f32 / pkt_times.len() as f32;
    let avg_delta_time = pkt_times.iter()
        .map(|&t| (avg_time - t as f32).abs())
        .sum::<f32>() / pkt_times.len() as f32;
    return [
        num_blocks as f32, ip_count as f32, tcp_count as f32,
        udp_count as f32, icmp_count as f32, arp_count as f32,
        http_count as f32, dhcp_count as f32, addresses.len() as f32,
        ports.len() as f32, bytes as f32, data_bytes as f32,
        avg_size, avg_deltas_size, avg_time, avg_delta_time
    ];
}

fn main() -> Result<(), Box<dyn Error>> {
    const WANNA_TRAIN: bool = true;  // or else eval

    let normal = File::open("pingNormal.pcapng").unwrap();
    let normal = get_stats(normal);
    let not_normal = File::open("pingNotNormal.pcapng").unwrap();
    let not_normal = get_stats(not_normal);
    let unreachable = File::open("pingUnreachable.pcapng").unwrap();
    let unreachable = get_stats(unreachable);

    let mut model_path = env::temp_dir();
    model_path.push("tf-pcapgn-analyze-model");
    match std::fs::remove_dir_all(&model_path) {
        Err(e) => {
            if e.kind() != ErrorKind::NotFound {
                return Err(Box::new(e));
            }
        }
        Ok(_) => {}
    }
    const TRUE: f32 = 100.0;
    const FALSE: f32 = 0.0;
    train(&model_path, &[
        (normal, (TRUE, FALSE, FALSE)),
        (not_normal, (FALSE, TRUE, FALSE)),
        (unreachable, (FALSE, FALSE, TRUE)),
    ])?;
    eval(&model_path, &[
        ("pingNormal".into(), normal, (TRUE, FALSE, FALSE)),
        ("pingNotNormal".into(), not_normal, (FALSE, TRUE, FALSE)),
        ("pingUnreachable".into(), unreachable, (FALSE, FALSE, TRUE)),
    ])?;
    Ok(())
}


// Helper for building a layer.
//
// `activation` is a function which takes a tensor and applies an activation
// function such as tanh.
//
// Returns variables created and the layer output.
fn layer<O1: Into<Output>>(
    input: O1,
    input_size: u64,
    output_size: u64,
    activation: &dyn Fn(Output, &mut Scope) -> Result<Output, Status>,
    scope: &mut Scope,
) -> Result<(Vec<Variable>, Output), Status>
{
    let mut scope = scope.new_sub_scope("layer");
    let scope = &mut scope;
    let w_shape = ops::constant(&[input_size as i64, output_size as i64][..], scope)?;
    let w = Variable::builder()
        .initial_value(
            ops::RandomStandardNormal::new()
                .dtype(DataType::Float)
                .build(w_shape, scope)?,
        )
        .data_type(DataType::Float)
        .shape([input_size, output_size])
        .build(&mut scope.with_op_name("w"))?;
    let b = Variable::builder()
        .const_initial_value(Tensor::<f32>::new(&[output_size]))
        .build(&mut scope.with_op_name("b"))?;
    Ok((
        vec![w.clone(), b.clone()],
        activation(
            ops::add(
                ops::mat_mul(input, w.output().clone(), scope)?,
                b.output().clone(),
                scope,
            )?
                .into(),
            scope,
        )?,
    ))
}

fn train<P: AsRef<Path>>(save_dir: P, train_data: &[([f32; 16], (f32, f32, f32))]) -> Result<(), Box<dyn Error>>
{
    // ================
    // Build the model.
    // ================
    let mut scope = Scope::new_root_scope();
    let scope = &mut scope;
    let hidden_size: u64 = 1024;
    let input = ops::Placeholder::new()
        .dtype(DataType::Float)
        .shape([1u64, 16])
        .build(&mut scope.with_op_name("input"))?;
    let label = ops::Placeholder::new()
        .dtype(DataType::Float)
        .shape([1u64, 3])
        .build(&mut scope.with_op_name("label"))?;
    // Hidden layer.
    let (vars1, layer1) = layer(
        input.clone(),
        16,
        hidden_size,
        &|x, scope| Ok(ops::tanh(x, scope)?.into()),
        scope,
    )?;
    // Output layer.
    let (vars2, layer2) = layer(
        layer1.clone(),
        hidden_size,
        3,
        &|x, _| Ok(x), scope,
    )?;
    let error = ops::sub(layer2.clone(), label.clone(), scope)?;
    let error_squared = ops::mul(error.clone(), error, scope)?;
    let mut optimizer = AdadeltaOptimizer::new();
    optimizer.set_learning_rate(ops::constant(1.0f32, scope)?);
    let mut variables = Vec::new();
    variables.extend(vars1);
    variables.extend(vars2);
    let (minimizer_vars, minimize) = optimizer.minimize(
        scope,
        error_squared.clone().into(),
        MinimizeOptions::default().with_variables(&variables),
    )?;

    let mut all_vars = variables.clone();
    all_vars.extend_from_slice(&minimizer_vars);
    let mut builder = tensorflow::SavedModelBuilder::new();
    builder
        .add_collection("train", &all_vars)
        .add_tag("serve")
        .add_tag("train")
        .add_signature(REGRESS_METHOD_NAME, {
            let mut def = SignatureDef::new(REGRESS_METHOD_NAME.to_string());
            def.add_input_info(
                REGRESS_INPUTS.to_string(),
                TensorInfo::new(
                    DataType::Float,
                    Shape::from(None),
                    OutputName {
                        name: input.name()?,
                        index: 0,
                    },
                ),
            );
            def.add_output_info(
                REGRESS_OUTPUTS.to_string(),
                TensorInfo::new(DataType::Float, Shape::from(None), layer2.name()?),
            );
            def
        });
    let saved_model_saver = builder.inject(scope)?;

    // =========================
    // Initialize the variables.
    // =========================
    let options = SessionOptions::new();
    let g = scope.graph_mut();
    let session = Session::new(&options, &g)?;
    let mut run_args = SessionRunArgs::new();
    // Initialize variables we defined.
    for var in &variables {
        run_args.add_target(&var.initializer());
    }
    // Initialize variables the optimizer defined.
    for var in &minimizer_vars {
        run_args.add_target(&var.initializer());
    }
    session.run(&mut run_args)?;

    // ================
    // Train the model.
    // ================
    let mut input_tensor = Tensor::<f32>::new(&[1, 16]);
    let mut label_tensor = Tensor::<f32>::new(&[1, 3]);
    // Helper that generates a training example from an integer, trains on that
    // example, and returns the error.
    let mut train = |stats: [f32; 16], res: (f32, f32, f32)| -> Result<(f32, f32, f32), Box<dyn Error>> {
        for i in 0..16 {
            input_tensor[i] = stats[i];
        }
        label_tensor[0] = res.0;
        label_tensor[1] = res.1;
        label_tensor[2] = res.2;
        let mut run_args = SessionRunArgs::new();
        run_args.add_target(&minimize);
        let error_squared_fetch = run_args.request_fetch(&error_squared, 0);
        run_args.add_feed(&input, 0, &input_tensor);
        run_args.add_feed(&label, 0, &label_tensor);
        session.run(&mut run_args)?;
        let fetched = run_args.fetch::<f32>(error_squared_fetch)?;
        Ok((fetched[0], fetched[1], fetched[2]))
    };
    for i in 0..1_000_000 {
        let (stats, res) = train_data[i % 3];
        train(stats, res)?;
    }

    // ================
    // Save the model.
    // ================
    saved_model_saver.save(&session, &g, &save_dir)?;
    println!("Model saved in {}", save_dir.as_ref().display());
    Ok(())
}

fn eval<P: AsRef<Path>>(save_dir: P, eval_data: &[(String, [f32; 16], (f32, f32, f32))]) -> Result<(), Box<dyn Error>> {
    let mut graph = Graph::new();
    let bundle = SavedModelBundle::load(
        &SessionOptions::new(),
        &["serve", "train"],
        &mut graph,
        save_dir,
    )?;
    let session = &bundle.session;
    let signature = bundle.meta_graph_def().get_signature(REGRESS_METHOD_NAME)?;
    let input_info = signature.get_input(REGRESS_INPUTS)?;
    let output_info = signature.get_output(REGRESS_OUTPUTS)?;
    let input_op = graph.operation_by_name_required(&input_info.name().name)?;
    let output_op = graph.operation_by_name_required(&output_info.name().name)?;

    let mut input_tensor = Tensor::<f32>::new(&[1, 16]);
    for (verbose, stats, target) in eval_data {
        for i in 0..16 {
            input_tensor[i] = stats[i];
        }
        let expected = [target.0, target.1, target.2];
        let mut run_args = SessionRunArgs::new();
        run_args.add_feed(&input_op, input_info.name().index, &input_tensor);
        let output_fetch = run_args.request_fetch(&output_op, output_info.name().index);
        session.run(&mut run_args)?;
        let fetched = run_args.fetch::<f32>(output_fetch)?;
        let output = (fetched[0], fetched[1], fetched[2]);
        println!("Result for {}: {:?}", verbose, output)
    }
    Ok(())
}
