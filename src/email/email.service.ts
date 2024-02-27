import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import * as argon from 'argon2';

interface EmailOptions {
  from?: string;
  to: string;
  subject: string;
  text?: string;
  html?: string;
}

@Injectable()
export class EmailService {
  constructor(private config: ConfigService) {}

  async sendEmail(options: EmailOptions): Promise<nodemailer.SentMessageInfo> {
    try {
      const transporter: nodemailer.Transporter = nodemailer.createTransport({
        host: this.config.get('SMTP_HOST'),
        port: this.config.get('SMTP_PORT'),
        auth: {
          user: this.config.get('SMTP_USERNAME'),
          pass: this.config.get('SMTP_PASSWORD'),
        },
      });

      const info = await transporter.sendMail({
        from: options.from || 'noreply@domain.com',
        to: options.to,
        subject: options.subject,
        text: options.text,
        html: options.html,
      });

      console.log('Message sent: %s', info.messageId);
      return info;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }

  async signUp(token: string, to: string): Promise<nodemailer.SentMessageInfo> {
    try {
      const subject = 'Verify Your Email Address';
      const text = `http://localhost:4000/auth/verify-email/${token}`;

      await this.sendEmail({ to, subject, text })
        .then((info) => console.log('Email sent:', info))
        .catch((error) => console.error('Error sending email:', error));
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }

  async forgotPassword(
    token: string,
    to: string,
  ): Promise<nodemailer.SentMessageInfo> {
    try {
      const subject = 'Forgot Password';
      const text = `http://localhost:4000/auth/reset-password/${token}`;

      await this.sendEmail({ to, subject, text })
        .then((info) => console.log('Email sent:', info))
        .catch((error) => console.error('Error sending email:', error));
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
}
