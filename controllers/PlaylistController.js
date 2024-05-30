import User from "../models/User.js";
import { addMovieInPlayList, createPlaylist, deleteMovieFromPlaylist, getAllPlaylist, getMoviesDetail, getPlaylistById, getPlaylistByIdForAUser } from "../services/PlaylistService.js";
import ErrorHandler from "../utils/ErrorHandler.js";

export const getAllPlaylists = async(req,res) => {
    const user = req.user;
    try {
        const playlists = await getAllPlaylist(user.id);
        return res.status(200).json({status: 200, data: playlists});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went Wrong"});
    }
}

export const createEmptyPlaylist = async(req,res) => {
    const user = req.user;
    try {
        const { playlistName, isPrivate } = req.body;
        await createPlaylist(playlistName, isPrivate, user.id);
        return res.status(201).json({status: 201, message: "Playlist created",success:true});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went wrong",success:false});
    }
}

export const createNewPlaylist = async(req,res) => {
    const user = req.user;
    try {
        const { playlistName, movieName, isPrivate } = req.body;
        await addMovieInPlayList(playlistName, user.id, movieName, isPrivate);
        return res.status(201).json({status: 201, message: "Playlist created"});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went wrong"});
    }
}


export const addMovieToPlaylist = async(req, res) => {
    const user = req.user;
    try {
        const { playlistName, movieName } = req.body;
        await addMovieInPlayList(playlistName, user.id, movieName);
        return res.status(201).json({status: 201, message: "Movie added"});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went wrong"});
    }
}

export const removeMovieFromPlaylist = async(req, res) => {
    const user = req.user;
    try {
        const { playlistName, movieName } = req.body;
        await deleteMovieFromPlaylist(playlistName, user.id, movieName);
        return res.status(201).json({status: 200, message: "Movie deleted"});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went wrong"});
    }
}


export const getPublicPlaylistById = async(req, res) => {
    const {playlistId} = req.params;
    try {
        const playlist = await getPlaylistById(playlistId);
        if (playlist && playlist.movies.length > 0) {
            const allMovies = [];
            for(const item of playlist.movies) {
                const movieDetail = await getMoviesDetail(item);
                allMovies.push({movieName: item, data: movieDetail});
            }
            const response = {_id:playlist._id, name: playlist.name, movies: allMovies};
            return res.status(201).json({status: 200, data: response});
        }
        return res.status(201).json({status: 200, data: playlist});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went wrong"});
    }
}

export const findPlaylistById = async(req, res) => {
    const user = req.user;
    const {playlistId} = req.params;
    if (!playlistId) {
        return res.status(404).json({status:404, message: "Please provide playlistId"});
    }
    try {
        const playlist = await getPlaylistByIdForAUser(playlistId, user.id);
        if (playlist && playlist.movies.length > 0) {
            const allMovies = [];
            for(const item of playlist.movies) {
                const movieDetail = await getMoviesDetail(item);
                allMovies.push({movieName: item, data: movieDetail});
            }
            const response = {_id:playlist._id, name: playlist.name, movies: allMovies};
            return res.status(201).json({status: 200, data: response});
        }
        return res.status(201).json({status: 200, data: playlist});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went wrong"});
    }
}

export const searchMovie = async(req, res) => {
    const {movieName} = req.query;
    if (!movieName) {
        return res.status(404).json({status: 404, message: "Please provide a movie name"});
    }
    try {
        const movie = await getMoviesDetail(movieName);
        return res.status(201).json({status: 200, data: movie});
    } catch (error) {
        return res.status(500).json({status: 500, message: "Something Went wrong"});
    }
}