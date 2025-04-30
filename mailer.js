const nodemailer = require('nodemailer');

// Создаём транспорт для отправки почты через Mail.ru
const transporter = nodemailer.createTransport({
  host: 'smtp.mail.ru',  // Используем правильный SMTP сервер Mail.ru
  port: 587,  // Для STARTTLS
  secure: false,  // false для STARTTLS
  auth: {
    user: 'beautyych@mail.ru',  // Ваш email на Mail.ru
    pass: 'e6myPi7gdtawvNNNvgC9'  // Ваш пароль приложения
  },
  tls: {
    rejectUnauthorized: false  // Разрешает подключение с самоподписанными сертификатами
  }
});

async function sendCode(email, code) {
  await transporter.sendMail({
    from: '"BeautyyCh" <beautyych@mail.ru>',
    to: email,
    subject: 'Код подтверждения',
    html: `<p>Ваш код подтверждения: <b>${code}</b></p>`,
  });
}

module.exports = { sendCode };
