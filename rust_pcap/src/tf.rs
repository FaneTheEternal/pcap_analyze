use std::error::Error;

use std::path::Path;

use tensorflow::{DataType, Graph, Operation, ops, Output, OutputName, REGRESS_INPUTS, REGRESS_METHOD_NAME, REGRESS_OUTPUTS, SavedModelBundle, SavedModelSaver, Scope, Session, SessionOptions, SessionRunArgs, Shape, SignatureDef, Status, Tensor, TensorInfo, train::{
    AdadeltaOptimizer,
    MinimizeOptions,
    Optimizer,
}, Variable};
use tracing::{info, Level, span, warn};

use crate::{default, fmt_iter};

// Helper for building a layer.
//
// `activation` is a function which takes a tensor and applies an activation
// function such as tanh.
//
// Returns variables created and the layer output.
fn layer<O: Into<Output>>(
    input: O,
    input_size: u64,
    output_size: u64,
    activation: &dyn Fn(Output, &mut Scope) -> Result<Output, Status>,
    scope: &mut Scope,
) -> Result<(Vec<Variable>, Output), Status>
{
    let scope = &mut scope.new_sub_scope("layer");
    let w_shape = ops::constant(&[input_size as i64, output_size as i64], scope)?;
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

pub struct TFBuilder {
    pub input: u64,
    pub output: u64,
    pub hidden: Vec<u64>,
    optimizer: Box<dyn Optimizer>,
    scope: Scope,
}

impl TFBuilder {
    pub fn new(input: u64, output: u64) -> Result<Self, Box<dyn Error>> {
        let mut scope = Scope::new_root_scope();
        let mut optimizer = AdadeltaOptimizer::new();
        // 0.001_f32
        optimizer.set_learning_rate(ops::constant(0.1_f32, &mut scope)?);
        // 0.95_f32
        optimizer.set_rho(ops::constant(0.95_f32, &mut scope)?);
        // 1e-8_f32
        optimizer.set_epsilon(ops::constant(1e-8_f32, &mut scope)?);
        Ok(Self {
            input,
            output,
            hidden: vec![],
            optimizer: Box::new(optimizer),
            scope,
        })
    }

    pub fn with_hidden<I>(mut self, hidden: I) -> Self
        where I: IntoIterator<Item=u64>
    {
        self.hidden = hidden.into_iter().collect();
        self
    }

    pub fn build(mut self) -> Result<TFNeuralNetwork, Box<dyn Error>> {
        let input = ops::Placeholder::new()
            .dtype(DataType::Float)
            .shape([1, self.input])
            .build(&mut self.scope.with_op_name("input"))?;
        let output = ops::Placeholder::new()
            .dtype(DataType::Float)
            .shape([1, self.output as u64])
            .build(&mut self.scope.with_op_name("output"))?;

        let (vars0, layer0) = layer(
            input.clone(),
            self.input,
            *self.hidden.first().unwrap_or(&self.output),
            &Self::relu,
            &mut self.scope,
        )?;
        let (vars_hidden, layer_hidden) = {
            let mut vars = Vec::new();
            let mut last_size = *self.hidden.first().unwrap_or(&self.output);
            let mut last_layer = layer0;
            if let Some(hidden) = self.hidden.get(1..) {
                for &hsize in hidden {
                    let (vars_n, layer_n) = layer(
                        last_layer,
                        last_size,
                        hsize,
                        &Self::relu,
                        &mut self.scope,
                    )?;
                    vars.extend(vars_n);
                    last_size = hsize;
                    last_layer = layer_n;
                }
            }
            (vars, last_layer)
        };
        let (vars_output, layer_output) = layer(
            layer_hidden,
            *self.hidden.last().unwrap(),
            self.output,
            &Self::pass,
            &mut self.scope,
        )?;
        let error = ops::sub(layer_output.clone(), output.clone(), &mut self.scope)?;
        let error_squared = ops::mul(error.clone(), error, &mut self.scope)?;
        let variables = vars0.into_iter()
            .chain(vars_hidden)
            .chain(vars_output)
            .collect::<Vec<_>>();
        let (minimizer_vars, minimize) = self.optimizer.minimize(
            &mut self.scope,
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
        let saver = builder.inject(&mut self.scope)?;
        let options = SessionOptions::new();
        let session = Session::new(&options, &self.scope.graph())?;

        Ok(TFNeuralNetwork {
            ctx: TFContext {
                input: self.input,
                output: self.output,
                hidden: self.hidden,
            },
            scope: self.scope,
            saver,
            session,
            variables,
            minimizer_vars,
            error_squared,
            input,
            output,
            minimize,
            restored: None,
        })
    }

    fn relu(x: Output, scope: &mut Scope) -> Result<Output, Status> {
        Ok(ops::relu(x, scope)?.into())
    }

    fn pass(x: Output, _scope: &mut Scope) -> Result<Output, Status> {
        Ok(x)
    }
}

struct TFContext {
    input: u64,
    output: u64,
    hidden: Vec<u64>,
}

pub struct TFNeuralNetwork {
    ctx: TFContext,
    scope: Scope,
    saver: SavedModelSaver,
    session: Session,
    variables: Vec<Variable>,
    minimizer_vars: Vec<Variable>,

    error_squared: Operation,
    input: Operation,
    output: Operation,
    minimize: Operation,

    restored: Option<RestoredModel>,
}

impl TFNeuralNetwork {
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let graph = self.scope.graph();
        self.saver.save(&self.session, &graph, path)?;
        Ok(())
    }

    pub fn name(&self) -> String {
        format!(
            "tf-model-{}-{}-{}",
            self.ctx.input,
            self.ctx.hidden.iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            self.ctx.output
        )
    }

    pub fn train(&mut self, cfg: &TrainConfig, data: &[(Vec<f32>, Vec<f32>)])
                 -> Result<Vec<Vec<f32>>, Box<dyn Error>>
    {
        if data.is_empty() {
            warn!("Trying use empty data set!");
            return Ok(default());
        }
        let span = span!(Level::INFO, "TRAIN", "{}", self.name());
        let _enter = span.enter();
        info!("APPLY {}", data.len());
        let mut run_args = SessionRunArgs::new();
        for var in &self.variables {
            run_args.add_target(var.initializer())
        }
        for var in &self.minimizer_vars {
            run_args.add_target(var.initializer());
        }
        self.session.run(&mut run_args)?;

        let mut in_tensor = Tensor::<f32>::new(&[1, self.ctx.input]);
        let mut out_tensor = Tensor::<f32>::new(&[1, self.ctx.output]);
        let mut train = |row: &[f32], target: &[f32]| -> Result<Vec<f32>, Box<dyn Error>> {
            in_tensor.copy_from_slice(row);
            out_tensor.copy_from_slice(target);
            let mut run_args = SessionRunArgs::new();
            run_args.add_target(&self.minimize);
            let error_squared_fetch = run_args.request_fetch(
                &self.error_squared, 0,
            );
            run_args.add_feed(&self.input, 0, &in_tensor);
            run_args.add_feed(&self.output, 0, &out_tensor);
            self.session.run(&mut run_args)?;
            let fetched = run_args.fetch::<f32>(error_squared_fetch)?;
            Ok(fetched.to_vec())
        };

        let width = cfg.epoch.to_string().chars().count();
        let mut total_errors: Vec<Vec<f32>> = vec![];
        for epoch in 0..=cfg.epoch {
            let mut errors = Vec::new();
            for (row, target) in data {
                errors.push(train(row, target)?);
            }
            if epoch % cfg.capture_period == 0 {
                let count = errors.len() as f32;
                let errors = errors.into_iter()
                    .fold(vec![0.0; self.ctx.output as usize], |r, e| {
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
                    epoch, cfg.epoch, fmt_iter!(errors, " ", "{:>12.5}"),
                    width = width,
                );
                total_errors.push(errors.try_into().unwrap());
            }
        }
        info!("FINAL ERROR SQUARED: {}", fmt_iter!(total_errors.last().unwrap(), " ", "{:^12}"));
        Ok(total_errors)
    }

    pub fn eval(&self, data: &[f32]) -> Result<Vec<f32>, Box<dyn Error>> {
        if data.len() != self.ctx.input as usize {
            return Err("".into());
        }
        let graph = self.scope.graph();
        let mut input_tensor = Tensor::<f32>::new(&[1, data.len() as u64]);
        let mut run_args = SessionRunArgs::new();
        input_tensor.copy_from_slice(data);
        let input_op = graph.operation_by_name_required("input")?;
        let output_op = graph.operation_by_name_required("output")?;
        run_args.add_feed(&input_op, 0, &input_tensor);
        let output_fetch = run_args.request_fetch(&output_op, 0);
        self.session.run(&mut run_args)?;
        let fetched = run_args.fetch::<f32>(output_fetch)?;
        Ok(fetched.to_vec())
    }

    pub fn restored_eval(&mut self, data: &[f32]) -> Result<Vec<f32>, Box<dyn Error>> {
        if self.restored.is_none() {
            info!("RESTORE...");
            let mut graph = Graph::new();
            let bundle = SavedModelBundle::load(
                &SessionOptions::new(),
                &["serve", "train"],
                &mut graph,
                self.name(),
            )?;
            let restored = RestoredModel { graph, bundle };
            self.restored.replace(restored);
        }
        let restored = self.restored.as_ref().unwrap();
        let graph = &restored.graph;
        let bundle = &restored.bundle;

        let session = &bundle.session;
        let signature = bundle.meta_graph_def().get_signature(REGRESS_METHOD_NAME)?;
        let input_info = signature.get_input(REGRESS_INPUTS)?;
        let output_info = signature.get_output(REGRESS_OUTPUTS)?;
        let input_op = graph.operation_by_name_required(&input_info.name().name)?;
        let output_op = graph.operation_by_name_required(&output_info.name().name)?;
        let mut input_tensor = Tensor::<f32>::new(&[1, data.len() as u64]);
        input_tensor.copy_from_slice(data);
        let mut run_args = SessionRunArgs::new();
        run_args.add_feed(&input_op, input_info.name().index, &input_tensor);
        let output_fetch = run_args.request_fetch(&output_op, output_info.name().index);
        session.run(&mut run_args)?;
        let fetched = run_args.fetch::<f32>(output_fetch)?;
        Ok(fetched.to_vec())
    }
}

pub struct TrainConfig {
    pub epoch: usize,
    pub capture_period: usize,
}

pub struct RestoredModel {
    graph: Graph,
    bundle: SavedModelBundle,
}
