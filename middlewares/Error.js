const errorMiddleware = (err, req, res, next) => {
  if (err.code === 11000) {
    err.message = "A user already exist with this email id";
    err.statusCode = 400;
  } else if (err.name === "ValidationError") {
    const messages = Object.values(err.errors).map((e) => e.message);
    err.message = messages;
    err.statusCode = 400;
  } else {
    err.message = err.message || "Internal Server Error";
    err.statusCode = err.statusCode || 500;
  }
  return res
    .status(err.statusCode)
    .send({ success: false, message: err.message });
};

export default errorMiddleware;
