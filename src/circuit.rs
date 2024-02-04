use std::collections::BTreeSet;

use ark_circom::circom::R1CSFile;
use ark_ff::Zero;

use acvm::{
    acir::{
        circuit::{Circuit, Opcode, PublicInputs},
        native_types::{Expression, Witness},
    },
    FieldElement,
};

pub(crate) fn acir_circuit_from_r1cs_file(r1cs_file: R1CSFile<ark_bn254::Bn254>) -> Circuit {
    let num_public_inputs = r1cs_file.header.n_pub_in;
    let num_public_outputs = r1cs_file.header.n_pub_out;
    let num_private_inputs = r1cs_file.header.n_prv_in;
    let num_variables = r1cs_file.header.n_wires;

    // In a circom circuit, the inputs are arranged in the order:
    //
    // 1. Public outputs
    // 2. Public inputs
    // 3. Private inputs
    let public_inputs_start = num_public_outputs;
    let private_inputs_start = public_inputs_start + num_public_inputs;

    let return_values: BTreeSet<Witness> = (0..public_inputs_start).map(Witness::from).collect();
    let public_parameters: BTreeSet<Witness> = (0..num_public_inputs)
        .map(|i| Witness::from(public_inputs_start + i))
        .collect();
    let private_parameters: BTreeSet<Witness> = (0..num_private_inputs)
        .map(|i| Witness::from(private_inputs_start + i))
        .collect();

    let opcodes = r1cs_file
        .constraints
        .into_iter()
        .map(|(a, b, c)| {
            let a_expr = r1cs_term_to_expr(a);
            let b_expr = r1cs_term_to_expr(b);
            let c_expr = r1cs_term_to_expr(c);

            let a_mul_b = (&a_expr * &b_expr).expect("`a` and `b` are both linear");
            Opcode::AssertZero(&a_mul_b - &c_expr)
        })
        .collect();

    Circuit {
        current_witness_index: num_variables,
        opcodes,
        private_parameters,
        public_parameters: PublicInputs(public_parameters),
        return_values: PublicInputs(return_values),
        assert_messages: Vec::new(),
    }
}

fn r1cs_term_to_expr(term: Vec<(usize, ark_bn254::Fr)>) -> Expression {
    let q_c = term
        .iter()
        .filter(|(wire_index, _)| *wire_index == 0)
        .fold(ark_bn254::Fr::zero(), |acc, (_, coeff)| acc + coeff);
    let q_c = FieldElement::from_repr(q_c);

    let linear_combinations = term
        .into_iter()
        .filter(|(wire_index, _)| *wire_index != 0)
        .map(|(wire_index, coefficient)| {
            (
                FieldElement::from_repr(coefficient),
                // Subtract off 1 as witness 0 is not implicitly equal to 1 anymore and so can be used.
                Witness(wire_index as u32 - 1),
            )
        })
        .collect();

    Expression {
        mul_terms: Vec::new(),
        linear_combinations,
        q_c,
    }
}
