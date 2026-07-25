#![allow(unused_imports)]

pub use crate::core::modbus::{
    read_coils, read_discrete_inputs, read_holding_registers, read_input_registers,
    write_multiple_coils, write_multiple_registers, write_single_coil, write_single_register,
    ModbusRegister, RegisterType,
};
