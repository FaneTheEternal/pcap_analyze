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

pub fn train<P: AsRef<Path>, const I: usize>(
    save_dir: P,
    train_data: &[([f32; I], (f32, f32, f32))],
) -> Result<(), Box<dyn Error>>
{
    // ================
    // Build the model.
    // ================
    let mut scope = Scope::new_root_scope();
    let scope = &mut scope;
    let hidden_size: u64 = 1024;
    let input = ops::Placeholder::new()
        .dtype(DataType::Float)
        .shape([1u64, I as u64])
        .build(&mut scope.with_op_name("input"))?;
    let label = ops::Placeholder::new()
        .dtype(DataType::Float)
        .shape([1u64, 3])
        .build(&mut scope.with_op_name("label"))?;
    // Hidden layer.
    let (vars1, layer1) = layer(
        input.clone(),
        I as u64,
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
    let mut input_tensor = Tensor::<f32>::new(&[1, I as u64]);
    let mut label_tensor = Tensor::<f32>::new(&[1, 3]);
    // Helper that generates a training example from an integer, trains on that
    // example, and returns the error.
    let mut train = |stats: [f32; I], res: (f32, f32, f32)| -> Result<(f32, f32, f32), Box<dyn Error>> {
        for i in 0..I {
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
    for epoch in 0..1_000_000 {
        let mut last = None;
        for (row, res) in train_data {
            last = Some(train(row.clone(), res.clone())?);
        }
        if epoch % 10 == 0 {
            println!("EPOCH:\t{} ERROR:\t{:?}", epoch, last.unwrap())
        }
    }

    // ================
    // Save the model.
    // ================
    saved_model_saver.save(&session, &g, &save_dir)?;
    println!("Model saved in {}", save_dir.as_ref().display());
    Ok(())
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