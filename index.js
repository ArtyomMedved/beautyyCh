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
const nodemailer = require("nodemailer");
const checkSession = require('./checkSession');

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

// Настройка временного хранилища multer (можно менять)
const tmpUploadDir = path.join(__dirname, "tmp_uploads");

if (!fs.existsSync(tmpUploadDir)) {
  fs.mkdirSync(tmpUploadDir);
}

const tempStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, tmpUploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  },
});

const upload = multer({ storage: tempStorage });

// Подключение к БД
const db = mysql.createPool({
  host: "localhost",
  user: "admin",
  password: "AdminPass456!",
  database: "exampledb",
});

const transporter = nodemailer.createTransport({
  host: "smtp.mail.ru",
  port: 587,
  secure: false,
  auth: {
    user: "beautyych@mail.ru",
    pass: "e6myPi7gdtawvNNNvgC9", // Используй пароль приложения!
  },
  tls: {
    rejectUnauthorized: false,
  },
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

// Укажи список страниц, которые надо мониторить
const protectedRoutes = [
  '/Training_list',
  '/adm_upload',
  '/course_description',
  '/course_full',
  '/requests_for_payment_approvals',
];

// Подключаем middleware
app.use(checkSession(protectedRoutes));


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
      "SELECT id, name, email, avatar, admin FROM users WHERE session_token = ?",
      [token]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Сессия не найдена" });
    }

    const user = rows[0];
    res.json(user); // теперь с id, name, email, avatar, admin
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
      await db.query(
        "UPDATE users SET session_token = NULL WHERE session_token = ?",
        [token]
      );

      // Очищаем cookie
      res.clearCookie("session", {
        httpOnly: true,
        secure: false, // true в продакшене с HTTPS
        sameSite: "strict",
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

// Роут для загрузки курса — загружаем 3 поля с файлами
app.post(
  "/upload-course",
  upload.fields([
    { name: "demo_video", maxCount: 1 },
    { name: "images", maxCount: 4 },
    { name: "full_video", maxCount: 1 },
  ]),
  async (req, res) => {
    const { title, description, price, features } = req.body;

    if (!title || !description || !price || !features) {
      return res.status(400).send("Все поля обязательны");
    }

    // Пути для папок
    const courseDir = path.join(__dirname, "public", title);
    const demoDir = path.join(courseDir, "demo");
    const courseVideoDir = path.join(courseDir, "course");

    try {
      // Создаем папки, если их нет
      if (!fs.existsSync(courseDir)) fs.mkdirSync(courseDir);
      if (!fs.existsSync(demoDir)) fs.mkdirSync(demoDir);
      if (!fs.existsSync(courseVideoDir)) fs.mkdirSync(courseVideoDir);

      // Сохраняем demo_video в папку demo
      if (req.files["demo_video"] && req.files["demo_video"].length > 0) {
        const demoVideoFile = req.files["demo_video"][0];
        const demoVideoPath = path.join(demoDir, demoVideoFile.originalname);
        fs.renameSync(demoVideoFile.path, demoVideoPath);
      } else {
        return res.status(400).send("Демо-видео не загружено");
      }

      // Сохраняем фотографии курса в папку demo
      if (req.files["images"] && req.files["images"].length > 0) {
        for (const file of req.files["images"]) {
          const imgPath = path.join(demoDir, file.originalname);
          fs.renameSync(file.path, imgPath);
        }
      } else {
        return res.status(400).send("Фотографии курса не загружены");
      }

      // Сохраняем полное видео курса в папку course
      if (req.files["full_video"] && req.files["full_video"].length > 0) {
        const fullVideoFile = req.files["full_video"][0];
        const fullVideoPath = path.join(
          courseVideoDir,
          fullVideoFile.originalname
        );
        fs.renameSync(fullVideoFile.path, fullVideoPath);
      } else {
        return res.status(400).send("Полное видео курса не загружено");
      }

      // Формируем пути для базы (относительно папки public)
      const demoVideoRelPath = `/${title}/demo/${req.files["demo_video"][0].originalname}`;
      const fullVideoRelPath = `/${title}/course/${req.files["full_video"][0].originalname}`;
      const imagesRelPaths = req.files["images"].map(
        (f) => `/${title}/demo/${f.originalname}`
      );

      // Вставляем данные в таблицу courses
      const [result] = await db.query(
        "INSERT INTO courses (title, description, price, features, demo_video, full_video) VALUES (?, ?, ?, ?, ?, ?)",
        [
          title,
          description,
          price,
          features,
          demoVideoRelPath,
          fullVideoRelPath,
        ]
      );

      const courseId = result.insertId;

      // Вставляем изображения в таблицу course_images с указанием is_main и sort_order
      for (let i = 0; i < imagesRelPaths.length; i++) {
        const imgPath = imagesRelPaths[i];
        const isMain = i === 0 ? 1 : 0; // первая фотка — главная
        const sortOrder = i; // порядок сортировки по индексу

        await db.query(
          "INSERT INTO course_images (course_id, image_url, is_main, sort_order) VALUES (?, ?, ?, ?)",
          [courseId, imgPath, isMain, sortOrder]
        );
      }

      res.status(200).send("Курс успешно загружен");
    } catch (error) {
      console.error("Ошибка при загрузке курса:", error);
      res.status(500).send("Ошибка сервера");
    }
  }
);

// Роут для получения всех курсов (демо)
app.get("/api/demo-courses", async (req, res) => {
  try {
    const [courses] = await db.execute(`
      SELECT 
        c.id, 
        c.title, 
        c.description, 
        c.price,
        i.image_url AS mainImage
      FROM courses c
      LEFT JOIN course_images i ON c.id = i.course_id AND i.is_main = 1
      ORDER BY c.created_at DESC
    `);

    res.json(courses);
  } catch (err) {
    console.error("Error fetching courses:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Роут для получения данных одного курса по ID (демо)
app.get("/api/demo-courses/:id", async (req, res) => {
  const courseId = req.params.id;

  try {
    const [courses] = await db.execute(
      `
      SELECT 
        c.id, 
        c.title, 
        c.description, 
        c.price,
        c.demo_video,
        c.full_video,
        c.features,
        i.image_url AS mainImage
      FROM courses c
      LEFT JOIN course_images i ON c.id = i.course_id AND i.is_main = 1
      WHERE c.id = ?
      LIMIT 1
    `,
      [courseId]
    );

    if (courses.length === 0) {
      return res.status(404).json({ message: "Курс не найден" });
    }

    res.json(courses[0]);
  } catch (err) {
    console.error("Error fetching course:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/user-courses/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const [courses] = await db.query(
      `
      SELECT 
        c.id,
        c.title,
        c.description,
        c.price,
        c.features,
        c.demo_video,
        c.full_video,
        uc.purchased_at,
        ci.image_url AS mainImage
      FROM user_courses uc
      JOIN courses c ON uc.course_id = c.id
      LEFT JOIN course_images ci ON ci.course_id = c.id AND ci.is_main = 1
      WHERE uc.user_id = ?
      ORDER BY uc.purchased_at DESC
      `,
      [userId]
    );

    res.json(courses);
  } catch (error) {
    console.error("Ошибка при получении купленных курсов:", error);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

app.post("/send-consultation", async (req, res) => {
  const { name, phone } = req.body;

  if (!name || !phone) {
    return res.json({ success: false, message: "Поля обязательны" });
  }

  const phonePattern = /^\+7\s\d{3}\s\d{3}-\d{2}-\d{2}$/;
  if (!phonePattern.test(phone)) {
    return res.json({ success: false, message: "Неверный формат телефона" });
  }

  const mailOptions = {
    from: "beautyych@mail.ru",
    to: "beautyych@mail.ru",
    subject: "Запрос на консультацию",
    text: `Пришёл запрос на получение консультации от: ${name}, телефон: ${phone}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true });
  } catch (error) {
    console.error("Ошибка отправки почты:", error);
    res.json({ success: false, message: "Ошибка сервера" });
  }
});

app.get("/course_description/:id", async (req, res) => {
  const courseId = req.params.id;

  try {
    // Получаем курс без выборки mainImage
    const [courseRows] = await db.query(
      `
      SELECT 
        id, title, description, price, features, 
        demo_video, full_video
      FROM courses
      WHERE id = ?
    `,
      [courseId]
    );

    if (courseRows.length === 0) {
      return res.status(404).send("Курс не найден");
    }

    const course = courseRows[0];

    // Получаем все изображения курса
    const [images] = await db.query(
      "SELECT image_url FROM course_images WHERE course_id = ? ORDER BY sort_order ASC",
      [courseId]
    );

    // Загружаем шаблон
    const templatePath = path.join(
      __dirname,
      "templates",
      "course_description.html"
    );
    let template = fs.readFileSync(templatePath, "utf8");

    // Заменяем плейсхолдеры
    template = template
      .replace(/{{title}}/g, course.title)
      .replace(/{{description}}/g, course.description)
      .replace(/{{price}}/g, course.price)
      .replace(/{{features}}/g, course.features)
      .replace(/{{demo_video}}/g, course.demo_video)
      .replace(/{{courseId}}/g, course.id); // добавили

    // Формируем HTML блок с изображениями
    const imagesHTML = images
      .map(
        (img) =>
          `<img src="${img.image_url}" alt="Course image" class="rounded-xl shadow w-64 h-auto" />`
      )
      .join("\n");

    template = template.replace(/{{images}}/g, imagesHTML);

    res.send(template);
  } catch (error) {
    console.error("Ошибка при загрузке страницы курса:", error);
    res.status(500).send("Ошибка сервера");
  }
});

// Проверка, есть ли заявка с такими параметрами
app.post("/api/payments/check", async (req, res) => {
  const { user_id, course_id } = req.body;

  try {
    const [rows] = await db.query(
      `SELECT COUNT(*) AS count FROM course_payments 
       WHERE user_id = ? AND course_id = ?`,
      [user_id, course_id]
    );
    res.json({ exists: rows[0].count > 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Сохранение заявки
app.post("/api/payments", async (req, res) => {
  const { user_id, user_name, course_id, course_title, payment_comment } =
    req.body;

  try {
    await db.query(
      `INSERT INTO course_payments 
       (user_id, user_name, course_id, course_title, payment_comment) 
       VALUES (?, ?, ?, ?, ?)`,
      [user_id, user_name, course_id, course_title, payment_comment]
    );
    res.status(200).json({ message: "Заявка сохранена" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Получить все запросы
app.get("/api/admin/requests", async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT cp.*, u.name AS user_name, c.title AS course_title
      FROM course_payments cp
      JOIN users u ON cp.user_id = u.id
      JOIN courses c ON cp.course_id = c.id
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка при получении заявок" });
  }
});

// Одобрить заявку
app.post("/api/admin/requests/:id/approve", async (req, res) => {
  const id = req.params.id;
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const [[payment]] = await conn.query(
      "SELECT * FROM course_payments WHERE id = ?",
      [id]
    );

    if (!payment) {
      await conn.rollback();
      return res.status(404).json({ error: "Заявка не найдена" });
    }

    await conn.query(
      "INSERT INTO user_courses (user_id, course_id) VALUES (?, ?)",
      [payment.user_id, payment.course_id]
    );

    await conn.query("DELETE FROM course_payments WHERE id = ?", [id]);

    await conn.commit();
    res.json({ success: true });
  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: "Ошибка при одобрении заявки" });
  } finally {
    conn.release();
  }
});

// Отклонить заявку
app.post("/api/admin/requests/:id/reject", async (req, res) => {
  try {
    await db.query("DELETE FROM course_payments WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Ошибка при отклонении заявки" });
  }
});

app.get("/my_course/:id", async (req, res) => {
  const courseId = req.params.id;

  try {
    const [courseRows] = await db.query(
      `
      SELECT 
        id, title, description, features, 
        full_video
      FROM courses
      WHERE id = ?
    `,
      [courseId]
    );

    if (courseRows.length === 0) {
      return res.status(404).send("Курс не найден");
    }

    const course = courseRows[0];

    const [images] = await db.query(
      "SELECT image_url FROM course_images WHERE course_id = ? ORDER BY sort_order ASC",
      [courseId]
    );

    const templatePath = path.join(__dirname, "templates", "course_full.html");
    let template = fs.readFileSync(templatePath, "utf8");

    // Подготовка списка фичей (разбиваем по строкам и оборачиваем в <li>)
    const featuresHTML = course.features
      .split("\n")
      .filter(Boolean)
      .map((line) => `<li>${line.trim()}</li>`)
      .join("\n");

    // Подготовка блока с видео
    const videoHTML = `
      <video controls preload="metadata">
        <source src="${course.full_video}" type="video/mp4" />
        Ваш браузер не поддерживает видео.
      </video>`;

    // Подготовка блока с изображениями
    const imagesHTML = images
      .map(
        (img) =>
          `<img src="${img.image_url}" alt="Пример работы" height="160" width="300" loading="lazy" />`
      )
      .join("\n");

    // Замена данных
    template = template
      .replace(/<h1>.*?<\/h1>/, `<h1>${course.title}</h1>`)
      .replace(
        /<p class="course-subtitle">.*?<\/p>/s,
        `<p class="course-subtitle">${course.description}</p>`
      )
      .replace(
        /<section aria-label="Демонстрационное видео курса" class="video-wrapper">[\s\S]*?<\/section>/,
        `
        <section aria-label="Полное видео курса" class="video-wrapper">
          ${videoHTML}
        </section>
      `
      )
      .replace(
        /<section aria-label="Галерея работ" class="gallery" tabindex="0">[\s\S]*?<\/section>/,
        `
        <section aria-label="Галерея работ" class="gallery" tabindex="0">
          ${imagesHTML}
        </section>
      `
      )
      .replace(
        /<ul class="features-list">[\s\S]*?<\/ul>/,
        `<ul class="features-list">${featuresHTML}</ul>`
      );

    res.send(template);
  } catch (error) {
    console.error("Ошибка при загрузке курса:", error);
    res.status(500).send("Ошибка сервера");
  }
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
