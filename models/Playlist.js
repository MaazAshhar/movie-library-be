import { Schema, model } from "mongoose";

const playlist = new Schema({
    name: {type: String, required: true},
    movies: [{type: String}],
    isPrivate: {type: Boolean, default: true}  
});

const Playlist = new model('Playlist', playlist);
export default Playlist;