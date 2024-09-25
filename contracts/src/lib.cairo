pub mod vrf_provider {
    pub mod vrf_provider;
    pub mod vrf_provider_component;
}

pub mod vrf_consumer {
    pub mod vrf_consumer_component;
    pub mod vrf_consumer_example;
}

pub mod utils;
use vrf_contracts::utils::{make_seed, get_as_caller};
use vrf_contracts::vrf_provider::vrf_provider_component::{IVrfDispatcher, IVrfDispatcherTrait};
#[cfg(test)]
mod tests;

