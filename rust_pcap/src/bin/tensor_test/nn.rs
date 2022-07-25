use std::error::Error;
use std::path::Path;

use tensorflow::{
    DataType,
    Graph,
    ops,
    Output,
    OutputName,
    REGRESS_INPUTS,
    REGRESS_METHOD_NAME,
    REGRESS_OUTPUTS,
    SavedModelBundle,
    Scope,
    Session,
    SessionOptions,
    SessionRunArgs,
    Shape,
    SignatureDef,
    Status,
    Tensor,
    TensorInfo, train::{AdadeltaOptimizer, MinimizeOptions, Optimizer}, Variable,
};
use tracing::{info, Level, span};

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

#[allow(dead_code)]
pub fn gtrain<P: AsRef<Path>, const I: usize, const O: usize>(
    save_dir: P,
    train_data: &[([f32; I], [f32; O])],
    hidden_layers: &[u64],
) -> Result<Vec<[f32; O]>, Box<dyn Error>>
{
    let mut model = GenericNeuralNetwork::new(
        hidden_layers,
        50_000, 100,
        Box::new(AdadeltaOptimizer::new()),
    );
    model.set_model_path(save_dir);
    model.train(train_data)
}

#[allow(dead_code)]
pub fn train<P: AsRef<Path>, const I: usize, const O: usize>(
    save_dir: P,
    train_data: &[([f32; I], [f32; O])],
) -> Result<(), Box<dyn Error>>
{
    gtrain(save_dir, train_data, &[256, 512, 128]).map(|_| ())
}

#[allow(dead_code)]
pub fn eval<P: AsRef<Path>>(
    save_dir: P,
    eval_data: &[(String, [f32; 16], (f32, f32, f32))],
) -> Result<(), Box<dyn Error>>
{
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

macro_rules! fmt_iter {
    ($iter:expr, $separator:expr, $fmt:tt) => {
        $iter.iter()
            .map(|e| format!($fmt, e))
            .collect::<Vec<_>>()
            .join($separator)
    };
    ($iter:expr, $separator:expr) => {
        fmt_iter!($iter, $separator, "{}")
    }
}

pub struct GenericNeuralNetwork<const I: usize, const O: usize> {
    pub hidden: Vec<u64>,
    pub epoch: usize,
    pub capture_period: usize,
    pub optimizer: Box<dyn Optimizer>,
    model_path: Box<dyn AsRef<Path>>,
}

impl<const I: usize, const O: usize> GenericNeuralNetwork<I, O> {
    fn _name(hidden: &[u64]) -> String {
        format!(
            "tf-model-{}-{}-{}",
            I,
            hidden.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>().join("-"),
            O
        )
    }

    pub fn new(
        hidden: &[u64],
        epoch: usize,
        capture_period: usize,
        optimizer: Box<dyn Optimizer>,
    ) -> Self
    {
        assert!(!hidden.is_empty());
        let model_path = Box::new(Self::_name(hidden));
        GenericNeuralNetwork {
            hidden: hidden.to_vec(),
            epoch,
            capture_period,
            optimizer: optimizer.into(),
            model_path,
        }
    }

    pub fn name(&self) -> String {
        Self::_name(&self.hidden)
    }

    pub fn set_model_path<P: AsRef<Path>>(&mut self, path: P) {
        self.model_path = Box::new(path.as_ref().to_str().unwrap().to_string())
    }

    pub fn model_path(&self) -> &dyn AsRef<Path> {
        self.model_path.as_ref()
    }

    pub fn train(
        &self,
        data: &[([f32; I], [f32; O])],
    ) -> Result<Vec<[f32; O]>, Box<dyn Error>>
    {
        let span = span!(Level::INFO, "TRAIN", "{}", self.name());
        let _enter = span.enter();

        info!("{} ROWS", data.len());
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
            *self.hidden.get(0).unwrap(),
            &|x, scope| Ok(ops::tanh(x, scope)?.into()),
            &mut scope,
        )?;
        let (vars_hidden, layer_hidden) = {
            let mut vars = Vec::new();
            let mut last_size = self.hidden.get(0).unwrap().clone();
            let mut last_layer = layer0.clone();
            for &hsize in self.hidden.get(1..).unwrap() {
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
            *self.hidden.last().unwrap(),
            O as u64,
            &|x, _| Ok(x),
            &mut scope,
        )?;
        let error = ops::sub(layer_output.clone(), output.clone(), &mut scope)?;
        let error_squared = ops::mul(error.clone(), error, &mut scope)?;
        let mut variables = Vec::new();
        variables.extend(vars0);
        variables.extend(vars_hidden);
        variables.extend(vars_output);
        let (minimizer_vars, minimize) = self.optimizer.minimize(
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
        let width = self.epoch.to_string().chars().count();
        let mut g_errors = Vec::<[f32; O]>::new();
        for epoch in 0..=self.epoch {
            let mut errors = Vec::new();
            for (row, target) in data {
                errors.push(train(row, target)?);
            }
            if epoch % self.capture_period == 0 {
                let count = errors.len() as f32;
                let errors = errors.into_iter()
                    .fold(vec![0.0; O], |r, e| {
                        r.into_iter()
                            .zip(e.into_iter())
                            .map(|(l, r)| { l + r })
                            .collect::<Vec<f32>>()
                    });
                let errors = errors.into_iter()
                    .map(|e| e / count)
                    .collect::<Vec<_>>();

                info!(
                    "[EPOCH {:>width$}/{}] ERROR SQUARED: {}",
                    epoch, self.epoch, fmt_iter!(errors, " ", "{:^12}"),
                    width = width,
                );
                g_errors.push(errors.try_into().unwrap());
            }
        }
        info!("FINAL ERROR SQUARED: {}", fmt_iter!(g_errors.last().unwrap(), " ", "{:^12}"));

        let save_dir = self.model_path();
        saver.save(&session, &graph, save_dir)?;
        info!("Model saved in {}", save_dir.as_ref().display());
        Ok(g_errors)
    }

    pub fn check(
        &self,
        data: &[([f32; I], [f32; O])],
    ) -> Result<[f32; O], Box<dyn Error>>
    {
        let span = span!(Level::INFO, "CHECK", "{}", self.name());
        let _enter = span.enter();

        info!("{} ROWS", data.len());

        let mut graph = Graph::new();
        let bundle = SavedModelBundle::load(
            &SessionOptions::new(),
            &["serve", "train"],
            &mut graph,
            self.model_path.as_ref(),
        )?;
        let session = &bundle.session;
        let signature = bundle.meta_graph_def().get_signature(REGRESS_METHOD_NAME)?;
        let input_info = signature.get_input(REGRESS_INPUTS)?;
        let output_info = signature.get_output(REGRESS_OUTPUTS)?;
        let input_op = graph.operation_by_name_required(&input_info.name().name)?;
        let output_op = graph.operation_by_name_required(&output_info.name().name)?;

        let mut input_tensor = Tensor::<f32>::new(&[1, I as u64]);
        let mut errors = Vec::new();
        for (row, target) in data {
            input_tensor.copy_from_slice(row);
            let mut run_args = SessionRunArgs::new();
            run_args.add_feed(&input_op, input_info.name().index, &input_tensor);
            let output_fetch = run_args.request_fetch(&output_op, output_info.name().index);
            session.run(&mut run_args)?;
            let fetched = run_args.fetch::<f32>(output_fetch)?;
            // let res = fetched.iter()
            //     .zip(target.iter())
            //     .map(|(f, t)| format!("{:^12}({:^12})", f, t))
            //     .collect::<Vec<_>>()
            //     .join(" ");
            // info!("{}", res);
            let error = fetched.iter()
                .zip(target)
                .map(|(f, t)| (f - t).abs())
                .collect::<Vec<_>>();
            errors.push(error);
        }
        let count = errors.len() as f32;
        let avg_err = errors.into_iter()
            .fold(vec![0f32; O], |acc, e| {
                acc.into_iter()
                    .zip(e)
                    .map(|(a, e)| a + e)
                    .collect::<Vec<_>>()
            })
            .into_iter()
            .map(|e| e / count)
            .collect::<Vec<f32>>();
        info!("AVG ERROR: {}", fmt_iter!(avg_err, " ", "{:^12}"));
        Ok(avg_err.try_into().unwrap())
    }
}
