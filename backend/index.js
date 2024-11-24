const express = require("express");
const { PORT } = require("./constants");
const { connectDB } = require("./config/db");
const { userRouter } = require("./routes/user.route");
const { redisMiddleware } = require("./middlewares/redis.middleware");
const { connectRedis } = require("./config/redis");

const app = express();

app.use(express.json());
app.use(redisMiddleware);

app.use("/api/v1/users", userRouter);

app.listen(PORT, async () => {
  try {
    await connectDB();
    console.log(`\n Server is running on port: http://localhost:${PORT}`);
    await connectRedis();
    console.log(`\n Connected to Redis cloud!`);
  } catch (error) {
    console.error("Database connection failed:", error.message);
  }
});
