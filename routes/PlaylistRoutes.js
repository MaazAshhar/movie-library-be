import { Router } from "express";
import { addMovieToPlaylist, createEmptyPlaylist, createNewPlaylist, findPlaylistById, getAllPlaylists, getPublicPlaylistById, removeMovieFromPlaylist, searchMovie } from "../controllers/PlaylistController.js";
import { userFromToken } from "../middlewares/JwtMiddleware.js";



const router = Router();

router.post('/createEmptyPlaylist', userFromToken, createEmptyPlaylist);
router.post('/createPlaylist', userFromToken, createNewPlaylist);
router.get('/getAllPlaylists', userFromToken, getAllPlaylists);
router.get('/getPlaylist/:playlistId', getPublicPlaylistById);
router.get('/getPlaylistForUser/:playlistId', userFromToken, findPlaylistById);
router.post('/addMovieToPlaylist', userFromToken, addMovieToPlaylist);
router.delete('/removeMovieFromPlaylist', userFromToken, removeMovieFromPlaylist);
router.get('/getMovie', userFromToken, searchMovie);


export default router;