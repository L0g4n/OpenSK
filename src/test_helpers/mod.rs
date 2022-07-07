// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::api::attestation_store::{self, Attestation, AttestationStore};
use crate::clock::CtapInstant;
use crate::ctap::command::{
    AuthenticatorAttestationMaterial, AuthenticatorConfigParameters, Command,
};
use crate::ctap::data_formats::ConfigSubCommand;
use crate::ctap::status_code::Ctap2StatusCode;
use crate::ctap::{key_material, Channel, CtapState};
use crate::env::Env;

// In tests where we define a dummy user-presence check that immediately returns, the channel
// ID is irrelevant, so we pass this (dummy but valid) value.
const DUMMY_CHANNEL: Channel = Channel::MainHid([0x12, 0x34, 0x56, 0x78]);

pub fn enable_enterprise_attestation(
    state: &mut CtapState,
    env: &mut impl Env,
) -> Result<AuthenticatorAttestationMaterial, Ctap2StatusCode> {
    let attestation_material = AuthenticatorAttestationMaterial {
        certificate: vec![0xdd; 20],
        private_key: [0x41; key_material::ATTESTATION_PRIVATE_KEY_LENGTH],
    };

    let attestation = Attestation {
        private_key: attestation_material.private_key,
        certificate: attestation_material.certificate.clone(),
    };
    env.attestation_store()
        .set(&attestation_store::Id::Enterprise, Some(&attestation))?;

    let config_params = AuthenticatorConfigParameters {
        sub_command: ConfigSubCommand::EnableEnterpriseAttestation,
        sub_command_params: None,
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
    };
    let config_command = Command::AuthenticatorConfig(config_params);
    state.process_parsed_command(env, config_command, DUMMY_CHANNEL, CtapInstant::new(0))?;

    Ok(attestation_material)
}
