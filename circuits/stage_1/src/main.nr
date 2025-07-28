fn main(today: pub u32, dob: u32) {
    let age_days: u32 = today - dob;
    assert(age_days >= 6570);
}