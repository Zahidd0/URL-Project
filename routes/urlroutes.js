

const express = require('express');
const router = express.Router();
const {createShortUrl,redirectUrl} = require('../controller/urlcontroller')

// Show form


// Handle form submission
router.post('/', createShortUrl);

// Handle redirection
router.get('/:id', redirectUrl );

module.exports = router;
