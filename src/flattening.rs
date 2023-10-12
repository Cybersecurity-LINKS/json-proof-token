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