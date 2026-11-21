// Fixture vibe-coded backend: CORS wide open.
const cors = require("cors");
app.use(cors({ origin: "*" }));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});
