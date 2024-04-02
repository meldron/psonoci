// use std::fs;
// use std::io::Write;
// use std::process::{Command, Stdio};

// fn run_ssh_command_with_key(ssh_key: &str, ssh_command: &str) -> std::io::Result<()> {
//     // Define the shell script
//     let shell_script = format!(
//         r#"
//         #!/bin/sh
//         eval "$(ssh-agent -s)" && \
//         ssh-add - && \
//         {}"#,
//         ssh_command
//     );

//     // Execute the shell script
//     let mut child = Command::new("sh")
//         .arg("-c")
//         .arg(&shell_script)
//         .stdin(Stdio::piped())
//         .spawn()?;

//     {
//         let stdin = child.stdin.as_mut().expect("Failed to open stdin");
//         writeln!(stdin, "{}", ssh_key)?;
//     }

//     // Wait for the script to complete and check the result
//     let output = child.wait_with_output()?;

//     // Check if the script executed successfully
//     if output.status.success() {
//         println!("Command executed successfully");
//     } else {
//         eprintln!("Error executing command");
//         if !output.stderr.is_empty() {
//             eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
//         }
//     }

//     Ok(())
// }

// fn main() {
//     // Example usage
//     let ssh_key = fs::read_to_string("/path/to/.ssh/key").expect("error reading key");
//     let ssh_command = "ssh root@example.local";

//     if let Err(e) = run_ssh_command_with_key(&ssh_key, ssh_command) {
//         eprintln!("Error: {}", e);
//     }
// }