use starknet::ContractAddress;
use stark_vrf::ecvrf::{Point, Proof, ECVRF, ECVRFImpl};

#[starknet::interface]
trait IVrfProvider<TContractState> {
    fn request_random(
        ref self: TContractState,
        consumer: ContractAddress,
        key: felt252,
        as_caller: bool,        
    ) -> felt252;

    fn submit_random(ref self: TContractState, seed: felt252, proof: Proof);

    fn consume_random(ref self: TContractState, caller: ContractAddress, key: felt252) -> felt252;

    fn get_random(self: @TContractState, seed: felt252) -> felt252;

    fn get_nonce(
        self: @TContractState, consumer: ContractAddress, caller: ContractAddress, key: felt252
    ) -> felt252;

    fn get_seed_for_call(
        self: @TContractState,
        caller: ContractAddress,
        key: felt252,
    ) -> felt252;

    fn get_commit(
        self: @TContractState, consumer: ContractAddress, caller: ContractAddress, key: felt252
    ) -> felt252;

    fn get_status(self: @TContractState, seed: felt252) -> RequestStatus;

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
    Fulfilled,
}


#[derive(Drop, Copy, Clone, Serde, starknet::Store)]
pub struct PublicKey {
    x: felt252,
    y: felt252,
}

impl PublicKeyIntoPoint of Into<PublicKey, Point> {
    fn into(self: PublicKey) -> Point {
        Point { x: self.x, y: self.y }
    }
}

#[starknet::component]
pub mod VrfProviderComponent {
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
        // (contract_address, caller_address, key) -> salt
        VrfProvider_commit: Map<(ContractAddress, ContractAddress, felt252), felt252>,
        // seed -> status
        VrfProvider_request_status: Map<felt252, RequestStatus>,
        // seed -> random
        VrfProvider_request_random: Map<felt252, felt252>,
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
        pub const INVALID_NONCE: felt252 = 'VrfProvider: invalid nonce';
        pub const ALREADY_COMMITTED: felt252 = 'VrfProvider: already committed';
        pub const ALREADY_REQUESTED: felt252 = 'VrfProvider: already requested';
        pub const ALREADY_FULFILLED: felt252 = 'VrfProvider: already fulfilled';
    }

    #[embeddable_as(VrfProviderImpl)]
    impl VrfProvider<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        impl Owner: OwnableComponent::HasComponent<TContractState>,
    > of super::IVrfProvider<ComponentState<TContractState>> {
        fn get_nonce(
            self: @ComponentState<TContractState>,
            consumer: ContractAddress,
            caller: ContractAddress,
            key: felt252,
        ) -> felt252 {
            self.VrfProvider_nonces.read((consumer, caller, key)) + 1
        }

        // directly called by user to request randomness for a contract / entrypoint / calldata
        fn request_random(
            ref self: ComponentState<TContractState>,
            consumer: ContractAddress,
            key: felt252,
            as_caller: bool,
        ) -> felt252 {

            let caller = get_as_caller(as_caller);

            // revert if user already requesting
            let is_committed = self.is_committed(consumer, caller, key);
            assert(!is_committed, Errors::ALREADY_COMMITTED);

            let nonce = self.VrfProvider_nonces.read((consumer, caller, key)) + 1;
            self.VrfProvider_nonces.write((consumer, caller, key), nonce);

            let seed = make_seed(consumer, caller, key, nonce);
            self.commit(consumer, caller, key, seed);

            self.VrfProvider_request_status.write(seed, RequestStatus::Received);
            self
                .emit(
                    RequestRandom {consumer, caller, key, nonce, seed}
                );
            seed
        }
        
        // called by executors
        fn submit_random(ref self: ComponentState<TContractState>, seed: felt252, proof: Proof) {
            // TODO: check allowed ?
            // self.accesscontrol.assert_only_executor();

            // check status
            let curr_status = self.VrfProvider_request_status.read(seed);
            assert(curr_status != RequestStatus::Fulfilled, Errors::ALREADY_FULFILLED);

            // verify proof
            let pubkey: Point = self.get_public_key().into();
            let ecvrf = ECVRFImpl::new(pubkey);

            let random = ecvrf.verify(proof.clone(), array![seed.clone()].span()).unwrap();
            
            // write random
            self.VrfProvider_request_random.write(seed, random);
            // update request status
            self.VrfProvider_request_status.write(seed, RequestStatus::Fulfilled);

            self.emit(SubmitRandom { seed, proof });
        }

        // called by consumer contract to retrieve current seed for for a contract / entrypoint / calldata
        fn get_seed_for_call(
            self: @ComponentState<TContractState>,
            caller: ContractAddress,
            key: felt252,
        ) -> felt252 {
            self.get_seed(get_caller_address(), caller,  key)
        }

        fn get_commit(
            self: @ComponentState<TContractState>,
            consumer: ContractAddress,
            caller: ContractAddress,
            key: felt252
        ) -> felt252 {
            self.VrfProvider_commit.read((consumer, caller, key))
        }

        fn get_status(self: @ComponentState<TContractState>, seed: felt252) -> RequestStatus {
            self.VrfProvider_request_status.read(seed)
        }
        fn consume_random(
            ref self: ComponentState<TContractState>, caller: ContractAddress, key: felt252
        ) -> felt252 {
            let consumer = get_caller_address();
            // clear user commit
            self.clear_commit(consumer, caller, key);
            self.VrfProvider_request_random.read(self.get_seed(consumer, caller, key))
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
        fn get_seed(self: @ComponentState<TContractState>, consumer: ContractAddress, caller: ContractAddress, key: felt252) -> felt252 {
            let nonce = self.VrfProvider_nonces.read((consumer, caller, key));
            make_seed(consumer, caller, key, nonce)
        }
        fn _set_public_key(ref self: ComponentState<TContractState>, new_pubkey: PublicKey) {
            assert(new_pubkey.x != 0 && new_pubkey.y != 0, Errors::PUBKEY_ZERO);
            self.VrfProvider_pubkey.write(new_pubkey);

            self.emit(PublicKeyChanged { pubkey: new_pubkey })
        }

        fn is_committed(
            self: @ComponentState<TContractState>,
            consumer: ContractAddress,
            caller: ContractAddress,
            key: felt252,
        ) -> bool {
            self.VrfProvider_commit.read((consumer, caller, key)) != 0
        }

        fn commit(
            ref self: ComponentState<TContractState>,
            consumer: ContractAddress,
            caller: ContractAddress,
            key: felt252,
            seed: felt252
        ) {
            self.VrfProvider_commit.write((consumer, caller, key), seed)
        }

        fn clear_commit(
            ref self: ComponentState<TContractState>,
            consumer: ContractAddress,
            caller: ContractAddress,
            key: felt252,
        ) {
            self.VrfProvider_commit.write((consumer, caller, key), 0)
        }
    }
}
