use starknet::ContractAddress;
use stark_vrf::ecvrf::{Point, Proof, ECVRF, ECVRFImpl};
use core::num::traits::Zero;


#[starknet::interface]
trait IVrfProvider<TContractState> {
    fn request_random(
        ref self: TContractState, consumer: ContractAddress, key: felt252, as_caller: bool,
    ) -> felt252;

    fn submit_random(ref self: TContractState, seed: felt252, proof: Proof);

    fn consume_random(ref self: TContractState, caller: ContractAddress, key: felt252) -> felt252;

    fn get_random(self: @TContractState, seed: felt252) -> felt252;

    fn get_seed_for_call(self: @TContractState, caller: ContractAddress, key: felt252,) -> felt252;

    fn get_status(self: @TContractState, caller: ContractAddress, key: felt252) -> RequestStatus;

    fn is_submitted(self: @TContractState, seed: felt252) -> bool;

    fn is_consumed(self: @TContractState, seed: felt252) -> bool;

    fn get_public_key(self: @TContractState) -> PublicKey;

    fn set_public_key(ref self: TContractState, new_pubkey: PublicKey);
}


//
//
//

#[derive(Drop, Clone, Serde)]
pub struct Request {
    consumer: ContractAddress,
    caller: ContractAddress,
    key: felt252,
    nonce: felt252,
}

#[generate_trait]
impl RequestImpl of RequestTrait {
    fn hash(self: @Request) -> felt252 {
        let mut keys: Array<felt252> = array![];
        self.serialize(ref keys);

        core::poseidon::poseidon_hash_span(keys.span())
    }
}

#[derive(Drop, Copy, Clone, Serde, PartialEq, starknet::Store)]
pub enum RequestStatus {
    None,
    Received,
    Submitted,
    Fulfilled,
}


#[derive(Drop, Copy, Clone, Serde, starknet::Store)]
pub struct PublicKey {
    x: felt252,
    y: felt252,
}

impl PublicKeyZeroImpl of Zero<PublicKey> {
    fn zero() -> PublicKey {
        PublicKey { x: 0, y: 0 }
    }
    fn is_non_zero(self: @PublicKey) -> bool {
        self.x.is_non_zero() && self.y.is_non_zero()
    }
    fn is_zero(self: @PublicKey) -> bool {
        self.x.is_zero() && self.y.is_zero()
    }
}

impl PublicKeyIntoPoint of Into<PublicKey, Point> {
    fn into(self: PublicKey) -> Point {
        Point { x: self.x, y: self.y }
    }
}

#[starknet::component]
pub mod VrfProviderComponent {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::Map;

    use openzeppelin::access::ownable::{
        OwnableComponent, OwnableComponent::InternalImpl as OwnableInternalImpl
    };

    use super::{Request, RequestImpl, RequestTrait, RequestStatus, PublicKey};
    use vrf_contracts::{make_seed, get_as_caller};
    use stark_vrf::{ecvrf::{Point, Proof, ECVRF, ECVRFImpl}};

    #[storage]
    struct Storage {
        VrfProvider_pubkey: PublicKey,
        // (contract_address, caller_address, key) -> nonce
        VrfProvider_nonces: Map<(ContractAddress, ContractAddress, felt252), felt252>,
        // seed -> random
        VrfProvider_request_random: Map<felt252, felt252>,
        // seed -> consumed
        VrfProvider_request_consumed: Map<felt252, bool>,
    }

    #[derive(Drop, starknet::Event)]
    struct PublicKeyChanged {
        pubkey: PublicKey,
    }

    #[derive(Drop, starknet::Event)]
    struct RequestRandom {
        consumer: ContractAddress,
        caller: ContractAddress,
        key: felt252,
        nonce: felt252,
        seed: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct SubmitRandom {
        seed: felt252,
        proof: Proof,
    }

    #[derive(Drop, starknet::Event)]
    #[event]
    enum Event {
        PublicKeyChanged: PublicKeyChanged,
        RequestRandom: RequestRandom,
        SubmitRandom: SubmitRandom,
    }

    pub mod Errors {
        pub const PUBKEY_ZERO: felt252 = 'VrfProvider: pubkey is zero';
        pub const ALREADY_SUBMITTED: felt252 = 'VrfProvider: already submitted';
        pub const NOT_SUBMITTED: felt252 = 'VrfProvider: not submitted';
        pub const ALREADY_CONSUMED: felt252 = 'VrfProvider: already consumed';
    }

    #[embeddable_as(VrfProviderImpl)]
    impl VrfProvider<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        impl Owner: OwnableComponent::HasComponent<TContractState>,
    > of super::IVrfProvider<ComponentState<TContractState>> {
        // directly called by user to request randomness for a contract / entrypoint / calldata
        fn request_random(
            ref self: ComponentState<TContractState>,
            consumer: ContractAddress,
            key: felt252,
            as_caller: bool,
        ) -> felt252 {
            // get caller if as_caller else return 0x0
            let caller = get_as_caller(as_caller);

            let mut nonce = self.VrfProvider_nonces.read((consumer, caller, key));
            if nonce.is_non_zero() {
                assert(
                    self.is_consumed(self.get_seed(consumer, caller, key)),
                    'Previous request not consumed'
                );
            };
            nonce += 1;
            self.VrfProvider_nonces.write((consumer, caller, key), nonce);

            let seed = make_seed(consumer, caller, key, nonce);

            self.emit(RequestRandom { consumer, caller, key, nonce, seed });
            seed
        }

        // called by executors
        fn submit_random(ref self: ComponentState<TContractState>, seed: felt252, proof: Proof) {
            // TODO: check allowed ? Verification could either be by contract address of private key
            // via verify self.accesscontrol.assert_only_executor();

            // check status
            assert(!self.is_submitted(seed), Errors::ALREADY_SUBMITTED);

            // verify proof
            let pubkey: Point = self.get_public_key().into();
            let ecvrf = ECVRFImpl::new(pubkey);
            let random = ecvrf.verify(proof.clone(), array![seed.clone()].span()).unwrap();

            // write random
            self.set_random(seed, random);

            self.emit(SubmitRandom { seed, proof });
        }

        fn consume_random(
            ref self: ComponentState<TContractState>, caller: ContractAddress, key: felt252
        ) -> felt252 {
            let consumer = get_caller_address();
            let seed = self.get_seed(consumer, caller, key);

            let random = self.VrfProvider_request_random.read(seed);

            assert(random.is_non_zero(), Errors::NOT_SUBMITTED);
            assert(!self.is_consumed(seed), Errors::ALREADY_CONSUMED);

            random
        }

        // called by consumer contract to retrieve current seed for for a contract / entrypoint /
        // calldata
        fn get_seed_for_call(
            self: @ComponentState<TContractState>, caller: ContractAddress, key: felt252,
        ) -> felt252 {
            self.get_seed(get_caller_address(), caller, key)
        }

        fn get_status(
            self: @ComponentState<TContractState>, caller: ContractAddress, key: felt252
        ) -> RequestStatus {
            let consumer = get_caller_address();
            let seed = self.get_seed(consumer, caller, key);
            if self.is_consumed(seed) {
                RequestStatus::Fulfilled
            } else if self.is_submitted(seed) {
                RequestStatus::Submitted
            } else if self.VrfProvider_nonces.read((consumer, caller, key)).is_non_zero() {
                RequestStatus::Received
            } else {
                RequestStatus::None
            }
        }

        fn is_submitted(self: @ComponentState<TContractState>, seed: felt252) -> bool {
            self.VrfProvider_request_random.read(seed).is_non_zero()
        }

        fn is_consumed(self: @ComponentState<TContractState>, seed: felt252) -> bool {
            self.VrfProvider_request_consumed.read(seed)
        }


        fn get_random(self: @ComponentState<TContractState>, seed: felt252) -> felt252 {
            self.VrfProvider_request_random.read(seed)
        }

        fn get_public_key(self: @ComponentState<TContractState>) -> PublicKey {
            self.VrfProvider_pubkey.read()
        }

        fn set_public_key(ref self: ComponentState<TContractState>, new_pubkey: PublicKey) {
            let mut ownable_component = get_dep_component_mut!(ref self, Owner);
            ownable_component.assert_only_owner();

            self._set_public_key(new_pubkey);
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        fn initializer(ref self: ComponentState<TContractState>, pubkey: PublicKey) {
            self._set_public_key(pubkey);
        }

        fn assert_pubkey_set(self: @ComponentState<TContractState>) {
            assert(self.VrfProvider_pubkey.read().is_non_zero(), Errors::PUBKEY_ZERO);
        }

        fn get_seed(
            self: @ComponentState<TContractState>,
            consumer: ContractAddress,
            caller: ContractAddress,
            key: felt252
        ) -> felt252 {
            make_seed(consumer, caller, key, self.VrfProvider_nonces.read((consumer, caller, key)))
        }

        fn next_nonce(
            ref self: ComponentState<TContractState>,
            consumer: ContractAddress,
            caller: ContractAddress,
            key: felt252
        ) -> felt252 {
            let nonce = self.VrfProvider_nonces.read((consumer, caller, key)) + 1;
            self.VrfProvider_nonces.write((consumer, caller, key), nonce);
            nonce
        }

        fn _set_public_key(ref self: ComponentState<TContractState>, new_pubkey: PublicKey) {
            assert(new_pubkey.x != 0 && new_pubkey.y != 0, Errors::PUBKEY_ZERO);
            self.VrfProvider_pubkey.write(new_pubkey);

            self.emit(PublicKeyChanged { pubkey: new_pubkey })
        }

        fn set_random(ref self: ComponentState<TContractState>, seed: felt252, random: felt252) {
            self.VrfProvider_request_random.write(seed, random);
        }

        fn set_consumed(ref self: ComponentState<TContractState>, seed: felt252) {
            self.VrfProvider_request_consumed.write(seed, true);
        }
    }
}
