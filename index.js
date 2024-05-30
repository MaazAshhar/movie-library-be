import express, { urlencoded } from "express";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";
import connectDB from "./config/database.js";
import UserRoutes from "./routes/UserRoutes.js";
import PlaylistRoutes from "./routes/PlaylistRoutes.js";
import errorMiddleware from "./middlewares/Error.js";

dotenv.config();
const PORT = process.env.PORT;
const app =express();
app.use(express.json());
app.use(bodyParser.json());
app.use(urlencoded({extended:false}));
app.use(cors());
connectDB();

app.use('/',UserRoutes);
app.use('/api',PlaylistRoutes);
app.listen(PORT,()=>console.log(`app is running on port ${PORT}`));
app.use(errorMiddleware);