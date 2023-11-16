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


use flatten_json_object::{Flattener, ArrayFormatting};
use indexmap::IndexMap;
use serde_json::Value;

pub(crate) fn json_value_flattening(value: Value) -> IndexMap<String, Value>{
    let flattened = Flattener::new()
        .set_key_separator(".")
        .set_array_formatting(ArrayFormatting::Surrounded {
            start: "[".to_string(),
            end: "]".to_string()
        })
        .set_preserve_empty_arrays(false)
        .set_preserve_empty_objects(false)
        .flatten(&value).unwrap();

        
    let flattened_json_object: IndexMap<String, Value> = serde_json::from_value::<IndexMap<String, Value>>(flattened.clone()).unwrap();
    flattened_json_object
}