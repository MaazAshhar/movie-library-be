# Movie Library Backend (movie-library-be)

This is the backend of movie library application built using Express.js. It allows users to sign up, log in, create playlists, and add movies to these playlists. The playlists can be either public or private.

## Table of contenst
-[installation](##installation)


## installation
Steps to set up and run project locally

1. Clone the GitHub repository to your local machine
2. cd movie-library-be  (move to root directory of project)
3. Install mongodb and mongodb compass to your local machine
4. Install node to your local machine
5. Get the url to connect to local mongodb database
6. Create a .env file to project root folder
7. Write following environment variable to .env file
    PORT = 3000 (To run the application on 3000 port).
    DB = "mongodb://localhost:27017/movie_library"  (url to connect to local mongoDB database).
    JWT_SECRET_KEY = "sheirET@135diesGdsh" (Secret key for Jwt authentication).
    OMDB_API_KEY = "8c2fd024"  (Use this api key or you can generate your own from (https://www.omdbapi.com/)).

8. open terminal in root folder and write command "npm install" to install all the required dependency.
9. run command "npm start" to run the application.
