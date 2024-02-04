use ark_circom::circom::r1cs_reader::Header;
use indexmap::IndexSet;
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::BufRead,
    ops::Range,
};

use acvm::acir::native_types::Witness;
use noirc_abi::{Abi, AbiParameter, AbiReturnType, AbiType, AbiVisibility};

pub(crate) fn abi_from_symbols<R: BufRead>(r1cs_header: &Header, reader: R) -> Abi {
    let re = Regex::new(r"^\d+,(\d+),\d+,(?:\w+\.?)*\.(\w+)((?:\[\d+\])+)?$").unwrap();

    let mut array_accesses: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let find_array_indices = |indices_str: &str| -> Vec<u64> {
        indices_str[1..indices_str.len() - 1]
            .split("][")
            .map(|index_string| index_string.parse::<u64>().unwrap())
            .collect()
    };

    let num_public_inputs = r1cs_header.n_pub_in;
    let num_public_outputs = r1cs_header.n_pub_out;
    let num_private_inputs = r1cs_header.n_prv_in;
    let inputs_start = num_public_outputs;
    let inputs_end = inputs_start + num_public_inputs + num_private_inputs;

    let input_witnesses = (inputs_start..inputs_end).map(Witness::from).collect();
    let return_witnesses = (0..num_public_outputs).map(Witness::from).collect();

    let lines = &mut reader.lines();

    let mut return_values: IndexSet<String> = IndexSet::new();
    for line in lines.take(num_public_outputs as usize).flatten() {
        let x = re.captures(&line).unwrap();

        let name = x.get(2).unwrap().as_str();
        return_values.insert(name.to_string());

        if let Some(array_indices) = x.get(3) {
            let array_indices = find_array_indices(array_indices.as_str());

            let entry = array_accesses
                .entry(name.to_owned())
                .or_insert(array_indices.clone());

            for (index, current_val) in entry.iter_mut().enumerate() {
                *current_val = std::cmp::max(*current_val, array_indices[index]);
            }
        }
    }

    let mut public_inputs: IndexSet<String> = IndexSet::new();
    let mut variable_witnesses: BTreeMap<String, Vec<Witness>> = BTreeMap::new();

    for line in lines.take(num_public_inputs as usize).flatten() {
        let x = re.captures(&line).unwrap();
        let name = x.get(2).unwrap().as_str();
        public_inputs.insert(name.to_string());

        let witness_index = x.get(1).unwrap().as_str();
        let witness = Witness(witness_index.parse::<u32>().unwrap());
        let entry = variable_witnesses.entry(name.to_owned()).or_default();
        entry.push(witness);

        if let Some(array_indices) = x.get(3) {
            let array_indices = find_array_indices(array_indices.as_str());

            let entry = array_accesses
                .entry(name.to_owned())
                .or_insert(array_indices.clone());

            for (index, current_val) in entry.iter_mut().enumerate() {
                *current_val = std::cmp::max(*current_val, array_indices[index]);
            }
        }
    }

    let mut private_inputs: BTreeSet<String> = BTreeSet::new();
    for line in lines.take(num_private_inputs as usize).flatten() {
        let x = re.captures(&line).unwrap();
        let name = x.get(2).unwrap().as_str();
        private_inputs.insert(name.to_string());

        if let Some(array_indices) = x.get(3) {
            let array_indices = find_array_indices(array_indices.as_str());

            let entry = array_accesses
                .entry(name.to_owned())
                .or_insert(array_indices.clone());

            for (index, current_val) in entry.iter_mut().enumerate() {
                *current_val = std::cmp::max(*current_val, array_indices[index]);
            }
        }
    }

    let public_parameters: Vec<AbiParameter> = public_inputs
        .into_iter()
        .map(|name| AbiParameter {
            name: name.clone(),
            typ: array_type_from_nesting_info(array_accesses.get(&name).unwrap_or(&Vec::new())),
            visibility: AbiVisibility::Public,
        })
        .collect();

    let private_parameters: Vec<AbiParameter> = private_inputs
        .into_iter()
        .map(|name| AbiParameter {
            name: name.clone(),
            typ: array_type_from_nesting_info(array_accesses.get(&name).unwrap_or(&Vec::new())),
            visibility: AbiVisibility::Private,
        })
        .collect();

    let parameters: Vec<AbiParameter> = public_parameters
        .into_iter()
        .chain(private_parameters)
        .collect();

    let return_type = match return_values.len().cmp(&1) {
        std::cmp::Ordering::Less => None,
        std::cmp::Ordering::Equal => {
            let return_value_name = &return_values[0];
            Some(AbiReturnType {
                abi_type: array_type_from_nesting_info(
                    array_accesses.get(return_value_name).unwrap_or(&Vec::new()),
                ),
                visibility: AbiVisibility::Public,
            })
        }
        std::cmp::Ordering::Greater => {
            let fields: Vec<AbiType> = return_values
                .iter()
                .map(|name| {
                    array_type_from_nesting_info(array_accesses.get(name).unwrap_or(&Vec::new()))
                })
                .collect();

            Some(AbiReturnType {
                abi_type: AbiType::Tuple { fields },
                visibility: AbiVisibility::Public,
            })
        }
    };

    let param_witnesses = param_witnesses_from_abi_param(&parameters, input_witnesses);
    Abi {
        parameters,
        param_witnesses,
        return_type,
        return_witnesses,
    }
}

fn array_type_from_nesting_info(array_accesses: &[u64]) -> AbiType {
    if let Some((head, tail)) = array_accesses.split_first() {
        AbiType::Array {
            length: *head + 1,
            typ: Box::new(array_type_from_nesting_info(tail)),
        }
    } else {
        AbiType::Field
    }
}

// Takes each abi parameter and shallowly maps to the expected witness range in which the
// parameter's constituent values live.
fn param_witnesses_from_abi_param(
    abi_params: &[AbiParameter],
    input_witnesses: Vec<Witness>,
) -> BTreeMap<String, Vec<Range<Witness>>> {
    let mut idx = 0_usize;
    if input_witnesses.is_empty() {
        return BTreeMap::new();
    }

    abi_params
        .iter()
        .map(|param| {
            let num_field_elements_needed = param.typ.field_count() as usize;
            let param_witnesses = &input_witnesses[idx..idx + num_field_elements_needed];

            // It's likely that `param_witnesses` will consist of mostly incrementing witness indices.
            // We then want to collapse these into `Range`s to save space.
            let param_witnesses = collapse_ranges(param_witnesses);
            idx += num_field_elements_needed;
            (param.name.clone(), param_witnesses)
        })
        .collect()
}

/// Takes a vector of [`Witnesses`][`Witness`] and collapses it into a vector of [`Range`]s of [`Witnesses`][`Witness`].
fn collapse_ranges(witnesses: &[Witness]) -> Vec<Range<Witness>> {
    if witnesses.is_empty() {
        return Vec::new();
    }
    let mut wit = Vec::new();
    let mut last_wit: Witness = witnesses[0];

    for (i, witness) in witnesses.iter().enumerate() {
        if i == 0 {
            continue;
        };
        let witness_index = witness.witness_index();
        let prev_witness_index = witnesses[i - 1].witness_index();
        if witness_index != prev_witness_index + 1 {
            wit.push(last_wit..Witness(prev_witness_index + 1));
            last_wit = *witness;
        };
    }

    let last_witness = witnesses.last().unwrap().witness_index();
    wit.push(last_wit..Witness(last_witness + 1));

    wit
}
