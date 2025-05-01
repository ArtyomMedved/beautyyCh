const express = require("express");
const path = require("path");
const fs = require("fs");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { sendCode } = require("./mailer");
const multer = require("multer");
const { format } = require("date-fns-tz");

const app = express();
const PORT = 3000;

// Настройка хранилища для аватаров
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/avatars"); // убедись, что эта папка существует
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  },
});

const upload = multer({ storage });

// Подключение к БД
const db = mysql.createPool({
  host: "localhost",
  user: "admin",
  password: "AdminPass456!",
  database: "exampledb",
});

app.use((req, res, next) => {
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const userAgent = req.headers["user-agent"];
  const requestedPath = req.originalUrl;

  // Форматируем дату по МСК
  const moscowTime = format(new Date(), "yyyy-MM-dd HH:mm:ssXXX", {
    timeZone: "Europe/Moscow",
  });

  const logEntry = `[${moscowTime}] IP: ${ip}, User-Agent: ${userAgent}, Путь: ${requestedPath}\n`;
  fs.appendFile("user_actions.log", logEntry, () => {});
  next();
});

// Middleware
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Статическая маршрутизация
const templatesDir = path.join(__dirname, "templates");
app.get("/", (req, res) => res.sendFile(path.join(templatesDir, "index.html")));
fs.readdirSync(templatesDir).forEach((file) => {
  if (file.endsWith(".html") && file !== "index.html") {
    const route = "/" + file.replace(".html", "");
    app.get(route, (req, res) => {
      res.sendFile(path.join(templatesDir, file));
    });
  }
});

// Генерация 2-х факторки
function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Генерация токена
function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Регистрация
app.post("/register", upload.single("avatar"), async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Проверка, существует ли уже пользователь
    const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);
    if (existing.length > 0)
      return res.status(400).send("Email уже зарегистрирован");

    const code = generateCode();

    // Удаляем старые коды для этого email
    await db.query("DELETE FROM email_verification_codes WHERE email = ?", [
      email,
    ]);

    // Добавляем новый код
    await db.query(
      "INSERT INTO email_verification_codes (email, code, purpose) VALUES (?, ?, ?)",
      [email, code, "register"]
    );

    // Отправляем код на почту
    await sendCode(email, code);

    // Перенаправляем на ввод кода подтверждения
    fs.appendFile(
      "user_actions.log",
      `[${new Date().toISOString()}] Регистрируется пользователь: ${email}\n`,
      () => {}
    );
    res.redirect(
      `/auth_code?email=${encodeURIComponent(
        email
      )}&purpose=register&name=${encodeURIComponent(
        name
      )}&password=${encodeURIComponent(password)}`
    );
  } catch (error) {
    console.error("Ошибка при регистрации:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Авторизация
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0)
      return res.status(401).send("Неверный email или пароль");

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send("Неверный email или пароль");

    const code = generateCode();

    // Удаляем старые коды для этого email
    await db.query("DELETE FROM email_verification_codes WHERE email = ?", [
      email,
    ]);

    // Добавляем новый код
    await db.query(
      "INSERT INTO email_verification_codes (email, code, purpose) VALUES (?, ?, ?)",
      [email, code, "login"]
    );

    // Отправляем код на почту
    await sendCode(email, code);

    // Перенаправляем на ввод кода подтверждения
    fs.appendFile(
      "user_actions.log",
      `[${new Date().toISOString()}] Попытка входа: ${email}\n`,
      () => {}
    );
    res.redirect(`/auth_code?email=${encodeURIComponent(email)}&purpose=login`);
  } catch (error) {
    console.error("Ошибка при входе:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// 2-х факторка
app.post("/verify-code", async (req, res) => {
  const { code, email, purpose, name, password } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM email_verification_codes WHERE email = ? AND code = ? AND purpose = ? AND created_at >= NOW() - INTERVAL 10 MINUTE",
    [email, code, purpose]
  );

  if (rows.length === 0)
    return res.status(400).send("Неверный или просроченный код");

  await db.query(
    "DELETE FROM email_verification_codes WHERE email = ? AND purpose = ?",
    [email, purpose]
  );

  if (purpose === "register") {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sessionToken = generateToken();
    await db.query(
      "INSERT INTO users (name, email, password, avatar, session_token) VALUES (?, ?, ?, ?, ?)",
      [name, email, hashedPassword, "avatars/default.jpg", sessionToken]
    );

    res.cookie("session", sessionToken, {
      httpOnly: true, // включить для безопасности
      secure: false, // установить в true для использования HTTPS в продакшене
      sameSite: "strict",
      maxAge: 604800000, // 7 дней
    });

    fs.appendFile(
      "user_actions.log",
      `[${new Date().toISOString()}] Успешная регистрация: ${email}\n`,
      () => {}
    );

    return res.json({ redirectTo: "/profile" });
  } else if (purpose === "login") {
    const [userRows] = await db.query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);
    if (userRows.length === 0)
      return res.status(404).send("Пользователь не найден");

    const sessionToken = generateToken();
    await db.query("UPDATE users SET session_token = ? WHERE id = ?", [
      sessionToken,
      userRows[0].id,
    ]);

    res.cookie("session", sessionToken, {
      httpOnly: true, // включить для безопасности
      secure: false, // установить в true для использования HTTPS в продакшене
      sameSite: "strict",
      maxAge: 604800000, // 7 дней
    });

    fs.appendFile(
      "user_actions.log",
      `[${new Date().toISOString()}] Успешный вход: ${email}\n`,
      () => {}
    );

    return res.json({ redirectTo: "/profile" });
  }
});

app.get("/api/profile", async (req, res) => {
  const token = req.cookies.session;

  if (!token) {
    return res.status(401).json({ error: "Не авторизован" });
  }

  try {
    const [rows] = await db.query(
      "SELECT name, email, avatar FROM users WHERE session_token = ?",
      [token]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Сессия не найдена" });
    }

    const user = rows[0];
    res.json(user); // JSON с name, email, avatar
  } catch (err) {
    console.error("Ошибка при получении профиля:", err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/logout", async (req, res) => {
  const token = req.cookies.session;

  if (token) {
    try {
      // Удаляем токен из базы данных (обнуляем)
      await db.query("UPDATE users SET session_token = NULL WHERE session_token = ?", [token]);

      // Очищаем cookie
      res.clearCookie("session", {
        httpOnly: true,
        secure: false, // true в продакшене с HTTPS
        sameSite: "strict"
      });

      fs.appendFile(
        "user_actions.log",
        `[${new Date().toISOString()}] Выход из аккаунта, токен: ${token}\n`,
        () => {}
      );
    } catch (err) {
      console.error("Ошибка при выходе:", err);
      return res.status(500).send("Ошибка сервера при выходе");
    }
  }

  // Редирект или сообщение
  res.json({ redirectTo: "/" });
});

// Проверка подключения к БД и запуск сервера
async function startServer() {
  try {
    await db.query("SELECT 1");
    console.log("✅ Подключение к базе данных прошло успешно.");
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Сервер работает: http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("❌ Ошибка подключения к базе данных:", err.message);
    process.exit(1);
  }
}

startServer();
