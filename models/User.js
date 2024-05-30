import { Schema, model } from "mongoose";


const phoneRegex = /^\d{10,}$/;
const user = new Schema({
    name : {
        type : String,
        required : true
    },
    email : {
        type : String,
        required : true,
        unique : true,
        match: [/\S+@\S+\.\S+/, 'Please use a valid email address.']
    },
    password : {
        type : String,
        required : true
    },
    phone : {
        type : String,
        required : true,
        validate : {
            validator : (value)=>{
                return phoneRegex.test(value);
            },
            message : props => `${props.value} is not a valid phone number. It must be exactly 10 digits long and contain no spaces.`
        }
    },
    playlists:[{
        type: Schema.Types.ObjectId,
        ref: 'Playlist'
    }]
});

const User = new model('User',user);
export default User;