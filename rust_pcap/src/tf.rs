use std::error::Error;
use std::ops::Index;

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
    TensorInfo,
    train::{
        AdadeltaOptimizer,
        MinimizeOptions,
        Optimizer,
    },
    Variable,
};
use tracing::{info, Level, span};

use crate::{default, fmt_iter, to_string};

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

#[derive(Default)]
pub struct NNContext {
    pub input: u64,
    pub output: u64,
    pub save_dir: Option<String>,
    pub errors: Vec<Vec<f32>>,
    pub restored: Option<RestoredModel>,
}

pub struct RestoredModel {
    graph: Graph,
    bundle: SavedModelBundle,
}


pub struct NeuralNetwork {
    hidden: Vec<u64>,
    pub epoch: usize,
    pub capture_period: usize,
    pub optimizer: Box<dyn Optimizer>,
    pub ctx: Option<NNContext>,
    pub save_after_training: bool,
}

impl NeuralNetwork {
    pub fn new<H>(
        hidden: H,
        epoch: usize,
        capture_period: usize,
    ) -> Self
        where
            H: IntoIterator<Item=u64>,
    {
        let hidden = hidden.into_iter().collect::<Vec<_>>();
        assert!(!hidden.is_empty());
        Self {
            hidden,
            epoch,
            capture_period,
            optimizer: Box::new(AdadeltaOptimizer::new()),
            ctx: default(),
            save_after_training: true,
        }
    }

    pub fn name(&self) -> String {
        let hidden = self.hidden.iter()
            .map(to_string)
            .collect::<Vec<_>>()
            .join("-");
        match &self.ctx {
            None => {
                format!("tf-model-unknown-{}-unknown", hidden)
            }
            Some(ctx) => {
                format!("tf-model-{}-{}-{}", ctx.input, hidden, ctx.output)
            }
        }
    }

    pub fn model_path(&self) -> String {
        match self.ctx.as_ref().and_then(|e| e.save_dir.as_ref()) {
            None => { self.name() }
            Some(save_dir) => { save_dir.clone() }
        }
    }

    pub fn train(
        &mut self,
        data: &[(&[f32], &[f32])],
    ) -> Result<(), Box<dyn Error>>
    {
        if data.is_empty() {
            return Ok(());
        }
        info!("CREATE CONTEXT FOR {}...", self.name());
        let mut ctx = NNContext::default();
        {
            let first = data.get(0).unwrap();
            ctx.input = first.0.len() as u64;
            ctx.output = first.1.len() as u64;
        }
        self.ctx = Some(NNContext {
            input: ctx.input,
            output: ctx.output,
            ..default()
        });
        info!("DONE: {}", self.name());
        let span = span!(Level::INFO, "TRAIN", "{}", self.name());
        let _enter = span.enter();
        info!("APPLY {}", data.len());
        let scope = &mut Scope::new_root_scope();
        let input = ops::Placeholder::new()
            .dtype(DataType::Float)
            .shape([1u64, ctx.input])
            .build(&mut scope.with_op_name("input"))?;
        let output = ops::Placeholder::new()
            .dtype(DataType::Float)
            .shape([1u64, ctx.output as u64])
            .build(&mut scope.with_op_name("output"))?;
        let (vars0, layer0) = layer(
            input.clone(),
            ctx.input,
            *self.hidden.get(0).unwrap(),
            &|x, scope| Ok(ops::tanh(x, scope)?.into()),
            scope,
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
                    scope,
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
            ctx.output,
            &|x, _| Ok(x),
            scope,
        )?;
        let error = ops::sub(layer_output.clone(), output.clone(), scope)?;
        let error_squared = ops::mul(error.clone(), error, scope)?;
        let mut variables = Vec::new();
        variables.extend(vars0);
        variables.extend(vars_hidden);
        variables.extend(vars_output);
        let (minimizer_vars, minimize) = self.optimizer.minimize(
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
                    TensorInfo::new(
                        DataType::Float,
                        Shape::from(None),
                        layer_output.name()?,
                    ),
                );
                def
            });
        let saver = builder.inject(scope)?;
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

        let mut in_tensor = Tensor::<f32>::new(&[1, ctx.input]);
        let mut out_tensor = Tensor::<f32>::new(&[1, ctx.output]);

        let mut train = |row: &[f32], target: &[f32]| -> Result<Vec<f32>, Box<dyn Error>> {
            in_tensor.copy_from_slice(row);
            out_tensor.copy_from_slice(target);
            let mut run_args = SessionRunArgs::new();
            run_args.add_target(&minimize);
            let error_squared_fetch = run_args.request_fetch(&error_squared, 0);
            run_args.add_feed(&input, 0, &in_tensor);
            run_args.add_feed(&output, 0, &out_tensor);
            session.run(&mut run_args)?;
            let fetched = run_args.fetch::<f32>(error_squared_fetch)?;
            Ok(fetched.to_vec())
        };

        let width = self.epoch.to_string().chars().count();
        for epoch in 0..=self.epoch {
            let mut errors = Vec::new();
            for (row, target) in data {
                errors.push(train(row, target)?);
            }
            if epoch % self.capture_period == 0 {
                let count = errors.len() as f32;
                let errors = errors.into_iter()
                    .fold(vec![0.0; ctx.output as usize], |r, e| {
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
                ctx.errors.push(errors.try_into().unwrap());
            }
        }
        info!("FINAL ERROR SQUARED: {}", fmt_iter!(ctx.errors.last().unwrap(), " ", "{:^12}"));

        if self.save_after_training {
            let save_dir = self.model_path();
            saver.save(&session, &graph, &save_dir)?;
            info!("MODEL SAVED IN {}", save_dir);
        }
        self.ctx.replace(ctx);
        Ok(())
    }

    pub fn eval(
        &mut self,
        data: &[f32],
    ) -> Result<Vec<f32>, Box<dyn Error>>
    {
        let (graph, bundle) = {
            if let Some(restored) = self.ctx.as_ref()
                .and_then(|ctx| ctx.restored.as_ref()) {
                (&restored.graph, &restored.bundle)
            } else {
                info!("RESTORE...");
                let mut graph = Graph::new();
                let bundle = SavedModelBundle::load(
                    &SessionOptions::new(),
                    &["serve", "train"],
                    &mut graph,
                    self.model_path(),
                )?;
                let restored = RestoredModel { graph, bundle };
                if let Some(ctx) = self.ctx.as_mut() {
                    ctx.restored.replace(restored);
                } else {
                    let mut ctx = NNContext::default();
                    let signature = restored.bundle.meta_graph_def().get_signature(REGRESS_METHOD_NAME)?;
                    let input_info = signature.get_input(REGRESS_INPUTS)?;
                    let output_info = signature.get_output(REGRESS_OUTPUTS)?;
                    let shape = input_info.shape();
                    ctx.input = shape.index(0)
                        .or_else(|| { shape.index(1).clone() })
                        .or_else(|| { shape.index(2).clone() })
                        .unwrap() as u64;
                    let shape = output_info.shape();
                    ctx.output = shape.index(0)
                        .or_else(|| { shape.index(1).clone() })
                        .or_else(|| { shape.index(2).clone() })
                        .unwrap() as u64;
                    ctx.restored.replace(restored);
                    self.ctx.replace(ctx);
                }
                let restored = self.ctx.as_ref().unwrap()
                    .restored.as_ref().unwrap();
                (&restored.graph, &restored.bundle)
            }
        };

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
