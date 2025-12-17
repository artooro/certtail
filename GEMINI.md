# CertTail

CertTail is a command-line interface (CLI) program that monitors Google's Certificate Transparency (CT) logs in real-time. For each new certificate that is published to the log, CertTail prints the timestamp, issuer, and subject names to the console.

## How it Works

The program continuously polls a selected Certificate Transparency log for new entries. When a new entry is detected, it parses the certificate data and extracts the following information:

- **Timestamp:** The time at which the certificate was logged.
- **Issuer:** The entity that issued the certificate.
- **Subject:** The entity for which the certificate was issued.

The program uses the `github.com/google/certificate-transparency-go` library to interact with the CT logs and parse the certificate data.

## Getting Started

To build and run the program, you need to have Go installed on your system.

### 1. Install Dependencies

Before running the program for the first time, you need to download the required Go packages:

```bash
go mod download
```

### 2. Run the Program

To run the program, execute the following command in your terminal:

```bash
go run main.go
```

The program will start monitoring the CT log and will print the details of new certificates as they are published. To stop the program, press `Ctrl+C`.
