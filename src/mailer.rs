use lettre::{message::Mailbox, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::{config::SmtpConfig, errors::AppError};

#[derive(Clone)]
pub struct Mailer {
    client: AsyncSmtpTransport<Tokio1Executor>,
}

impl Mailer {
    pub fn new(config: SmtpConfig) -> Self {
        let client = if config.port == 1025 {
            // Development mode (e.g., MailHog) — no TLS
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(config.host)
                .port(config.port)
                .build()
        } else {
            // Production mode — use STARTTLS
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .expect("failed to create SMTP transport")
                .port(config.port)
                .build()
        };

        Self { client }
    }

    pub async fn send_email(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), AppError> {
        let message = Message::builder()
            .from(Mailbox::new(
                None,
                "noreply@rust-auth-template.local".parse()?,
            ))
            .to(Mailbox::new(None, recipient.parse()?))
            .subject(subject)
            .body(body.to_string())?;

        self.client.send(message).await?;
        Ok(())
    }
}
