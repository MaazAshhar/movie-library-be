import dotenv from 'dotenv';
import { connect } from 'mongoose';

dotenv.config();

const connectDB = ()=>{
    connect(process.env.DB)
    .then(()=>{console.log("connected to mongodb");})
    .catch((error)=>{
        console.log("No database connection",error);
        process.exit(1);
    });
}


export default connectDB;