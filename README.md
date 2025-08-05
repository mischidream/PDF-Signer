# PDF_Signature_BA

A Java application to digitally sign PDF documents using the [EU DSS (Digital Signature Services)](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Digital+Signature+Service+-++DSS) library. Supports both local CMS-based signing and remote A-Trust qualified signatures via command-line interface.

## Features

- Sign PDF documents with baseline PAdES signatures
- Supports both:
    - Local CMS-based signing
    - Remote A-Trust qualified signatures

## Requirements

- Java 17+
- Maven 3.8+

## Local Signing Preparation
The local signing procedure is only to see details on how it could work if we have a local certificate.
In principle, we want to use an EU trusted provider.

### Prepare an ECDSA key (you will need openssl installed on your system)
```bash
#create and go to key directory
mkdir src/main/java/org/example/0_Keys
cd src/main/java/org/example/0_Keys
#create private key
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
#generate corresponding public key
openssl ec -in private-key.pem -pubout -out public-key.pem
#create a self-signed certificate
# for the command below the entered details don't really matter for testing purposes
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360
#convert pem to pfx
# (!!!) you will need to enter ***   test  ***  as password (no stars, no whitespaces, just test)  
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx
```

### A-Trust Setup Preparation
Download the A-Trust Test Certificates to contact their API.

```bash
# create and go to key directory
mkdir src/main/java/org/example/0_Keys
cd src/main/java/org/example/0_Keys
# 
wget -O authentication_certificate.p12  https://github.com/A-Trust/ASignSealQualified/raw/master/test_credentials/authentication_certificate.p12

```

## Installation

1. **Clone or download the repository**
2. Build the project using Maven:

```bash
mvn clean package
```

This will generate a JAR file in the `target/` directory.

## Usage

Run the JAR file with:

```bash
java -jar target/your-project-name.jar <mode> <input.pdf> <output.pdf>
```

### Modes:

| Mode           | Description                                 |
|----------------|---------------------------------------------|
| `signDocument` | Uses custom external CMS signature flow    |
| `signWithATrust` | Signs using A-Trust qualified remote seal  |

### Example Usage

#### 1. Sign a PDF using external CMS logic:

```bash
java -jar target/pdf-signer-1.0-SNAPSHOT.jar signDocument ./src/main/java/org/example/1_Files/dummy.pdf ./src/main/java/org/example/1_Files/signed.pdf
```

#### 2. Sign using A-Trust remote signing:

```bash
java -jar target/pdf-signer-1.0-SNAPSHOT.jar signWithATrust ./src/main/java/org/example/1_Files/dummy.pdf ./src/main/java/org/example/1_Files/signed_with_atrust.pdf
```

## Testing

To test the application:

1. Place your PDF in `1_Files/dummy.pdf`
2. Ensure your `.p12` file is in `0_Keys/`
3. Use either `signPDFDocument` or `signWithATrust` modes
4. Check for the output in `1_Files/` folder
5. Validate signature here: https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
