const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");

const protect = asyncHandler(async (req, res, next) => {
  let token;

  // Vérifier si l'en-tête Authorization existe et commence par "Bearer"
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];

      // Décoder le token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Ajouter l'utilisateur à la requête
      req.user = await User.findById(decoded.id).select("-password");

      // Passer à la prochaine étape
      next();
    } catch (error) {
      console.log(error);
      res.status(401).json({ message: "You are not authorized" });
    }
  }

  // Si le token n'est pas présent
  if (!token) {
    res.status(401).json({ message: "No token, authorization denied" });
  }
});

module.exports = { protect };
