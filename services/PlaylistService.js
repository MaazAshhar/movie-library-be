import Playlist from "../models/Playlist.js"
import User from "../models/User.js";
import dotenv from 'dotenv';
dotenv.config();

export const createPlaylist = async(playlistName, isPrivate, userId, moviesList = []) => {
    const playList = new  Playlist({
        name: playlistName,
        movies: moviesList,
        isPrivate: isPrivate
    });
    await playList.save();
    const user = await User.findById(userId);
    if (user) {
        user.playlists.push(playList._id);
        await user.save();
    }
}

export const checkPlaylistExist = async(playlistName, userId) => {
    const user = await User.findById(userId).populate('playlists');
    if (user && user.playlists && user.playlists.length>0) {
        return user.playlists.some(playlist => playlist.name === playlistName);
    }
    return false;
}

export const getPlaylistByName = async(playlistName, userId) => {
    const user = await User.findById(userId).populate('playlists');
    if (user && user.playlists && user.playlists.length>0) {
        const playlist =  user.playlists.filter(playlist => playlist.name === playlistName);
        return playlist.length>0? playlist[0]:null;
    }
    return null;
}

export const getAllPlaylist = async(userId) => {
    const user = await User.findById(userId).populate('playlists');
    return user.playlists;
}

export const addMovieInPlayList = async(playlistName, userId, movieName, isPrivate=false) => {
    playlistName?.forEach(async playlist => {
        const myPlaylist = await getPlaylistByName(playlist, userId);
        if (myPlaylist && !playlist.movies?.some(item => item === movieName)) {
            myPlaylist.movies.push(movieName);
            await myPlaylist.save();
        }
    });
}

export const deleteMovieFromPlaylist = async(playlistName, userId, movieName) => {
    const playlist = await getPlaylistByName(playlistName, userId);
    if (playlist) {
        playlist.movies = playlist.movies.filter(item => item !== movieName);
        await playlist.save();
    }
}

export const getPlaylistById = async(playlistId) => {
    const playlist = await Playlist.findById(playlistId);
    return (playlist && !playlist.isPrivate)?playlist: null;
}

export const getPlaylistByIdForAUser = async(playlistId, userId) => {
    const playlist = await Playlist.findById(playlistId);
    if (!playlist) {
        return null;
    }
    if (!playlist.isPrivate) {
        return playlist;
    }
    const allPlaylists = await getAllPlaylist(userId);
    const myPlaylist = Array.from(allPlaylists).filter(item => {
        return item._id.toString() === playlistId;
    });
    return (myPlaylist.length > 0)? myPlaylist[0]: null;
}

export const getMoviesDetail = async(movieName) => {
    const apiKey = process.env.OMDB_API_KEY;
    const url = `http://www.omdbapi.com/?t=${movieName}&apikey=${apiKey}`;
    const response = await (await fetch(url)).json();
    return response;
}