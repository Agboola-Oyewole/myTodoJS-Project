import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
  ssl: true
});
db.connect();

function formatDate(date) {
  const options = { day: "numeric", month: "long", year: "numeric" };
  const formattedDate = new Date(date).toLocaleDateString("en-US", options);
  const day = new Date(date).getDate();
  const suffix =
    day === 1 || day === 21 || day === 31
      ? "st"
      : day === 2 || day === 22
      ? "nd"
      : day === 3 || day === 23
      ? "rd"
      : "th";
  const formattedWithSuffix = formattedDate.replace(
    /\b\d{1,2}\b/,
    day + suffix
  );
  return formattedWithSuffix;
}

async function loadAllTodos(user_id) {
  const result = await db.query(
    "SELECT * FROM todos WHERE user_id = $1 ORDER BY id DESC",
    [user_id]
  );
  const userTodos = result.rows;
  return userTodos;
}

async function loadActiveTodos(user_id) {
  const result = await db.query(
    "SELECT * FROM todos WHERE user_id = $1 AND active = true ORDER BY id DESC",
    [user_id]
  );
  const userTodos = result.rows;
  return userTodos;
}

async function loadCompletedTodos(user_id) {
  const result = await db.query(
    "SELECT * FROM todos WHERE user_id = $1 AND completed = true ORDER BY id DESC",
    [user_id]
  );
  const userTodos = result.rows;
  return userTodos;
}

app.get("/home", async (req, res) => {
  if (req.isAuthenticated()) {
    // console.log(req.user)
    try {
      const currentUser = req.user;
      const userTodos = await loadAllTodos(req.user.id);
      const userActiveTodos = await loadActiveTodos(req.user.id);
      const userCompletedTodos = await loadCompletedTodos(req.user.id);
      res.render("home.ejs", {
        user: currentUser,
        userTodos: userTodos,
        userActiveTodos: userActiveTodos,
        userCompletedTodos: userCompletedTodos,
      });
    } catch (error) {
      console.log(error);
    }
  } else {
    res.redirect("/");
  }
});

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/home");
  } else {
    res.render("register.ejs");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/home",
    failureRedirect: "/",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
  });
  res.redirect("/");
});

app.post("/update", async (req, res) => {
  const todoName = req.body.todoName;
  const todoId = req.body.updatedItemId;
  const today = formatDate(new Date());
  try {
    await db.query(
      "UPDATE todos SET name = $1, date_updated = $2 WHERE id = $3",
      [todoName, today, todoId]
    );
  } catch (error) {
    console.log(error);
  }
  res.redirect("/home");
});

app.post("/add", async (req, res) => {
  const todoName = req.body.todoName;
  const today = formatDate(new Date());
  try {
    await db.query(
      "INSERT INTO todos (name, user_id, date_created) VALUES ($1, $2, $3)",
      [todoName, req.user.id, today]
    );
  } catch (error) {
    console.log(error);
  }
  res.redirect("/home");
});

app.post("/delete", async (req, res) => {
  const todoId = req.body.deletedItemId;
  await db.query("DELETE FROM todos WHERE id = $1", [todoId]);
  res.redirect("/home");
});

app.post("/completed", async (req, res) => {
  const todoId = req.body.updateTodoId;
  const today = formatDate(new Date());
  try {
    await db.query(
      "UPDATE todos SET completed = true, active = false, date_completed = $1 WHERE id = $2",
      [today, todoId]
    );
  } catch (error) {
    console.log(error);
  }
  res.redirect("/home");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.email;
  const username = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [username, email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/home");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// TODO1: FIND WHATS WRONG HERE
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://mytodojs-project.onrender.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [profile.given_name, profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

