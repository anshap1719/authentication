package email

import (
	"fmt"
	m "github.com/keighl/mandrill"
	"os"
)

func GetMandrillClient() *m.Client {
	return m.ClientWithKey(os.Getenv("MandrillAPIKey"))
}

func SendVerificationEmail(email, name, url string) error {
	client := GetMandrillClient()

	message := &m.Message{
		FromEmail: "noreply@domain.com",
		FromName:  "Support",
		Subject:   "Verify Your Email",
		GlobalMergeVars: m.MapToVars(map[string]string{
			"CONFIRM_EMAIL_TARGET": url,
		}),
	}

	message.AddRecipient(email, name, "to")

	if resp, err := client.MessagesSendTemplate(message, "Confirm Email", nil); err != nil {
		fmt.Println(resp, err)
		return err
	}

	return nil
}

func SendResetPassword(email, name, url string) error {
	client := GetMandrillClient()

	message := &m.Message{
		FromEmail: "noreply@domain.com",
		FromName:  "Support",
		Subject:   "Reset Your Password",
		GlobalMergeVars: m.MapToVars(map[string]string{
			"RESET_PASSWORD": url,
		}),
	}

	message.AddRecipient(email, name, "to")

	if resp, err := client.MessagesSendTemplate(message, "Reset Password", nil); err != nil {
		fmt.Println(resp, err)
		return err
	}

	return nil
}

func SendWelcomeEmail(email, name string) {
	client := GetMandrillClient()

	message := &m.Message{}
	message.AddRecipient(email, name, "to")

	templateContent := map[string]string{
		"FNAME": name,
	}

	if _, err := client.MessagesSendTemplate(message, "welcome", templateContent); err != nil {
		fmt.Println(err)
	}
}

func SendNotificationEmail(email, name, subject, content string) {
	client := GetMandrillClient()

	message := &m.Message{}
	message.AddRecipient(email, name, "to")
	message.Subject = subject

	templateContent := map[string]string{
		"FNAME":   name,
		"CONTENT": content,
	}

	if _, err := client.MessagesSendTemplate(message, "notify-user", templateContent); err != nil {
		fmt.Println(err)
	}
}
