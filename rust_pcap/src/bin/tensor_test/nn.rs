use std::error::Error;
use std::path::Path;
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

pub fn gtrain<P: AsRef<Path>, const I: usize, const O: usize>(
    save_dir: P,
    train_data: &[([f32; I], [f32; O])],
    hidden_layers: &[u64],
) -> Result<(), Box<dyn Error>>
{
    assert!(!hidden_layers.is_empty());

    let mut scope = Scope::new_root_scope();
    let input = ops::Placeholder::new()
        .dtype(DataType::Float)
        .shape([1u64, I as u64])
        .build(&mut scope.with_op_name("input"))?;
    let output = ops::Placeholder::new()
        .dtype(DataType::Float)
        .shape([1u64, O as u64])
        .build(&mut scope.with_op_name("output"))?;
    let (vars0, layer0) = layer(
        input.clone(),
        I as u64,
        *hidden_layers.get(0).unwrap(),
        &|x, scope| Ok(ops::tanh(x, scope)?.into()),
        &mut scope,
    )?;
    let (vars_hidden, layer_hidden) = {
        let mut vars = Vec::new();
        let mut last_size = hidden_layers.get(0).unwrap().clone();
        let mut last_layer = layer0.clone();
        for &hsize in hidden_layers.get(1..).unwrap() {
            let (vars_n, layer_n) = layer(
                last_layer,
                last_size,
                hsize,
                &|x, scope| Ok(ops::tanh(x, scope)?.into()),
                &mut scope,
            )?;
            vars.extend(vars_n);
            last_size = hsize;
            last_layer = layer_n;
        }
        (vars, last_layer)
    };
    let (vars_output, layer_output) = layer(
        layer_hidden,
        *hidden_layers.last().unwrap(),
        O as u64,
        &|x, _| Ok(x),
        &mut scope,
    )?;
    let error = ops::sub(layer_output.clone(), output.clone(), &mut scope)?;
    let error_squared = ops::mul(error.clone(), error, &mut scope)?;
    let mut optimizer = AdadeltaOptimizer::new();
    let mut variables = Vec::new();
    variables.extend(vars0);
    variables.extend(vars_hidden);
    variables.extend(vars_output);
    let (minimizer_vars, minimize) = optimizer.minimize(
        &mut scope,
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
                TensorInfo::new(
                    DataType::Float,
                    Shape::from(None),
                    layer_output.name()?,
                ),
            );
            def
        });
    let saver = builder.inject(&mut scope)?;

    let options = SessionOptions::new();
    let graph = scope.graph_mut();
    let session = Session::new(&options, &graph)?;
    let mut run_args = SessionRunArgs::new();
    for var in &variables {
        run_args.add_target(var.initializer())
    }
    for var in &minimizer_vars {
        run_args.add_target(var.initializer());
    }
    session.run(&mut run_args)?;

    let mut in_tensor = Tensor::<f32>::new(&[1, I as u64]);
    let mut out_tensor = Tensor::<f32>::new(&[1, O as u64]);
    let mut train = |row: &[f32; I], target: &[f32; O]| -> Result<[f32; O], Box<dyn Error>> {
        in_tensor.copy_from_slice(row);
        out_tensor.copy_from_slice(target);
        let mut run_args = SessionRunArgs::new();
        run_args.add_target(&minimize);
        let error_squared_fetch = run_args.request_fetch(&error_squared, 0);
        run_args.add_feed(&input, 0, &in_tensor);
        run_args.add_feed(&output, 0, &out_tensor);
        session.run(&mut run_args)?;
        let fetched = run_args.fetch::<f32>(error_squared_fetch)?;
        Ok(fetched.to_vec().try_into().unwrap())
    };
    for epoch in 0..50_000 {
        let mut errors = Vec::new();
        for (row, target) in train_data {
            errors.push(train(row, target)?);
        }
        if epoch % 100 == 0 {
            let count = errors.len() as f32;
            let errors = errors.into_iter()
                .fold(vec![0.0; O], |r, e| {
                    r.into_iter()
                        .zip(e.into_iter())
                        .map(|(l, r)| { l + r })
                        .collect::<Vec<f32>>()
                });
            let errors = errors.into_iter()
                .map(|e| format!("{}", e / count))
                .collect::<Vec<String>>().join("\t");
            println!("EPOCH:\t{}\tERROR SQUARED:\t{}", epoch, errors);
        }
    }

    saver.save(&session, &graph, &save_dir)?;
    println!("Model saved in {}", save_dir.as_ref().display());
    Ok(())
}

pub fn train<P: AsRef<Path>, const I: usize, const O: usize>(
    save_dir: P,
    train_data: &[([f32; I], [f32; O])],
) -> Result<(), Box<dyn Error>>
{
    gtrain(save_dir, train_data, &[256, 512, 128])
}

pub fn eval<P: AsRef<Path>>(save_dir: P, eval_data: &[(String, [f32; 16], (f32, f32, f32))]) -> Result<(), Box<dyn Error>> {
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
