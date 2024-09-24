use starknet::{ContractAddress, get_caller_address};
use core::num::traits::Zero;

pub fn make_seed(consumer: ContractAddress, caller: ContractAddress, key: felt252, nonce: felt252) -> felt252 {
    core::poseidon::poseidon_hash_span(array![consumer.into(), caller.into(), key, nonce].span())
}


pub fn get_as_caller(as_caller: bool) -> ContractAddress {
    if as_caller {
        get_caller_address()
    } else {
        Zero::zero()
    }
}