// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A JWP Header is a set of Header Parameters that apply to the JWP.
//! These Header Parameters may be specific to the proof applied to the JWP,
//! they may identify the party issuing the proof, and they may describe the
//! application purpose and format of the JWP, as well as provide other potential metadata.
//! See https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof-08#name-jwp-header
pub mod header;
pub mod issued;
pub mod presented;
