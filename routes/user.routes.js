// const express = require('express');
const router = require("express").Router();

const bcrypt = require("bcryptjs");
const saltRounds = 10;

const User = require("../models/User.model");

const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");

router.get("/", (req, res, next) => {
  res.render("index", { title: "Home page" })
})
router.post("/", (req, res, next) => {
  res.render("index", { title: "Home page" })
})

router.get("/register",  (req, res, next) => {
  res.render("users/register");
});

router.post("/register", (req, res, next) => {
  let { username, password, passwordRepeat } = req.body;
  if (username == "" || password == "" || passwordRepeat == "") {
    res.render("users/register", { messageError: "There are missing fields" });
    return;
  }
  else if (password != passwordRepeat) {
    res.render("users/register", { messageError: "The passwords do not match" });
    return;
  }

  User.find({ username })
    .then(results => {
      console.log("results ", results);
      if (results.length != 0) {
        //error
        res.render("users/register", { messageError: "The user already exists" });
        return;
      }

      let salt = bcrypt.genSaltSync(saltRounds);
      let encryptedPassword = bcrypt.hashSync(password, salt);

      User.create({
        username: username,
        password: encryptedPassword
      })
        .then(result => {
          res.redirect("/user/login");
        })
        .catch(err => next(err))
    })
    .catch(err => {
      console.log("err ", err);
      next(err);
    })

})

router.get("/login", isLoggedOut, (req, res, next) => {
  console.log("REQ.SESSION: ", req.session);
  res.render("users/login");
})

router.post("/login",  isLoggedOut, (req, res, next) => {
  let { username, password } = req.body;
  if (username == "" || password == "") {
    res.render("users/login", { messageError: "Missing fields" });
    return;
  }

  User.find({ username })
    .then(results => {
      if (results.length == 0) {
        res.render("users/login", { messageError: "Incorrect Credentials" });
        return;
      }


      if (bcrypt.compareSync(password, results[0].password)) {
        req.session.currentUser = username; //en req.session.currentUser guardamos la información del usuario que nos interese. Podemos guardar un string o un objeto con todos los datos
        res.redirect("/user/profile");
      } else {
        res.render("users/login", { messageError: "Incorrect Credentials" });
      }
    })
    .catch(err => next(err));

})

router.get("/profile", isLoggedIn, (req, res, next) => {
  res.render("users/profile", { username: req.session.currentUser });
})


router.get("/main", isLoggedOut,  (req, res, next) => {
  res.render("users/main");
})

router.get("/private", isLoggedIn,  (req, res, next) => {
  res.render("users/private");
})

router.get("/logout", isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    else res.redirect("/user/login");
  });
});

module.exports = router;