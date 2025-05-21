// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

// Package main implements sending out emails for new accounts
// as being read from an CSV file in the format `emailaddress,password`.
// where `emailaddress` is the username by convention.

package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"log"
	"net/smtp"
	"os"
	"strings"
	"text/template"
)

func check(err error) {
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

func sendMail(recipient, password, TCName string) error {
	smtpHost := "localhost"
	smtpPort := "25"
	emailFrom := "OASIS Quorum Calculator <no-reply@quorum.oasis-open.org>"
	//emailPassword := ""

	headers := "MIME-Version: 1.0\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"Content-Type: text/plain; charset=\"UTF-8\"\r\n"

	subject := "OQC - OASIS Quorum Calculator: Account creation"
	bodyTemplate := `Dear OASIS {{.TCName}} TC member,

an account was created for you at the OQC (https://quorum.oasis-open.org).

username: {{.Recipient}}
initial password: {{.Password}}

Please change your initial password.

Kind regards,
Your OQC Tool`

	tmpl, err := template.New("body").Parse(bodyTemplate)
	if err != nil {
		return err
	}

	data := struct {
		Recipient string
		Password  string
		TCName    string
	}{
		Recipient: recipient,
		Password:  password,
		TCName:    TCName,
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return (err)
	}
	body := buf.String()
	// make sure that mixed line endings are all \r\n
	norm_body := strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(norm_body, "\n", "\r\n")

	msg := []byte(
		"To: " + recipient + "\r\n" +
			"From: " + emailFrom + "\r\n" +
			"Subject: " + subject + "\r\n" +
			headers +
			"\r\n" +
			body + "\r\n",
	)

	//auth := smtp.PlainAuth("", emailFrom, emailPassword, smtpHost)

	err = smtp.SendMail(smtpHost+":"+smtpPort, nil, emailFrom, []string{recipient}, msg)
	if err != nil {
		log.Fatal("Failed to send email:", err)
	}
	log.Printf("Email to %s sent successfully!\n", recipient)

	return nil
}

func run(passwordCSV, TCName string) error {
	passwordsFile, err := os.Open(passwordCSV)
	if err != nil {
		return err
	}
	defer passwordsFile.Close()

	r := csv.NewReader(passwordsFile)
	records, err := r.ReadAll()
	if err != nil {
		return err
	}

	log.Printf("sending out emails for TC `%s`\n", TCName)

	for _, record := range records {
		err = sendMail(record[0], record[1], TCName)
		if err != nil {
			return err
		}
	}

	return nil

}

func main() {
	var (
		passwordCSV string
		TCName      string
	)

	flag.StringVar(&passwordCSV, "p", "passwords.csv", "CSV file of the list of users and passwords.")

	flag.StringVar(&TCName, "t", "", "Name of the TC to mention in the email.")
	flag.Parse()

	check(run(passwordCSV, TCName))
}
