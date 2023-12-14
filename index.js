require('dotenv').config();
const { Bot } = require('grammy');
const { ethers } = require('ethers');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const bot = new Bot(process.env.TELEGRAM_BOT_TOKEN);
const provider = new ethers.providers.JsonRpcProvider(`${process.env.PROVIDER}`);
const db = new sqlite3.Database('wallets.db');

// Function to encrypt data using AES-256
function encrypt(text, secretKey, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Function to decrypt data using AES-256
function decrypt(encryptedText, secretKey) {
  let textParts = encryptedText.split(':');
  let iv = Buffer.from(textParts.shift(), 'hex');
  let encrypted = Buffer.from(textParts.join(':'), 'hex');
  let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Function to generate a 32-byte key from the PIN
function getKeyFromPIN(pin, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(pin, salt, 100000, 32, 'sha512', (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey);
    });
  });
}

// Initialize database
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS users (userid TEXT, address TEXT, encryptedKey TEXT, salt TEXT)');
    db.run('CREATE TABLE IF NOT EXISTS user_states (userid TEXT, state TEXT)');
  });
// Command to start the bot and display a welcome message
bot.command('start', async (ctx) => {
    ctx.reply("Welcome to the Wallet Bot! Here's what you can do:\n" +
              "/newwallet - Create a new wallet\n" +
              "/balance - Check your wallet's balance\n" +
              "/showkey - Show your private key\n" +
              "/delete - Delete your wallet\n" +
              "Make sure to keep your PIN and private key safe!");
});

// Command to create a new wallet
bot.command('newwallet', async (ctx) => {
    db.get('SELECT address FROM users WHERE userid = ?', [ctx.from.id], async (err, row) => {
      if (err) {
        return console.error(err.message);
      }
      if (row) {
        ctx.reply("You already have a wallet. Use /delete to remove your current wallet.");
      } else {
        const wallet = ethers.Wallet.createRandom();
        const pin = Math.floor(100000 + Math.random() * 900000).toString();
        const salt = crypto.randomBytes(16);
        const key = await getKeyFromPIN(pin, salt);
        const iv = crypto.randomBytes(16);
        const encryptedKey = encrypt(wallet.privateKey, key, iv);
  
        db.run('INSERT INTO users (userid, address, encryptedKey, salt) VALUES (?, ?, ?, ?)', [ctx.from.id, wallet.address, encryptedKey, salt.toString('hex')], function(err) {
          if (err) {
            return console.error(err.message);
          }
          ctx.reply(`New wallet created! Address: ${wallet.address}\nYour PIN (keep it safe): ${pin}\nYour Private Key: ${wallet.privateKey}`).then(sentMessage => {
            setTimeout(() => {
              ctx.api.editMessageText(ctx.chat.id, sentMessage.message_id, `New wallet created! Address: ${wallet.address}\nYour PIN (keep it safe): ${pin}\nYour Private Key has been hidden for security.`);
            }, 10000);
          });
        });
      }
    });
});

  

// Command to delete a wallet
bot.command('delete', async (ctx) => {
    ctx.reply('Are you sure you want to delete your wallet? Type "yes delete my wallet" to confirm.');
    db.run('INSERT INTO user_states (userid, state) VALUES (?, ?)', [ctx.from.id, 'awaitingDeleteConfirmation']);
  });

// Command to get balance
bot.command('balance', async (ctx) => {
  db.get('SELECT address FROM users WHERE userid = ?', [ctx.from.id], async (err, row) => {
    if (err) {
      return console.error(err.message);
    }
    if (row) {
      const balance = await provider.getBalance(row.address);
      ctx.reply(`Balance: ${ethers.utils.formatEther(balance)} X`);
    } else {
      ctx.reply("No wallet created. Use /newwallet to create a wallet.");
    }
  });
});
const userStates = new Map();

// Command to show private key
bot.command('showkey', async (ctx) => {
    const userId = ctx.from.id;

    // Check if the user has a wallet in the database
    db.get('SELECT address FROM users WHERE userid = ?', [userId], async (err, row) => {
        if (err) {
            console.error(err.message);
            ctx.reply('An error occurred.');
            return;
        }

        if (row) {
            // If a wallet is found, proceed to ask for PIN
            ctx.reply('Please enter your PIN to decrypt your key:');
            db.run('INSERT INTO user_states (userid, state) VALUES (?, ?)', [userId, 'awaitingPIN'], function(err) {
                if (err) {
                    return console.error(err.message);
                }
            });
        } else {
            // If no wallet is found, inform the user to create one
            ctx.reply("No wallet created. Please use /newwallet to create a wallet.");
        }
    });
});


// General message handler
bot.on('message', async (ctx) => {
    const userId = ctx.from.id;
  
    // Check if the user has an awaiting state in the database
    db.get('SELECT state FROM user_states WHERE userid = ?', [userId], async (err, row) => {
    if (err) {
      console.error(err.message);
      ctx.reply('An error occurred.');
      return;
    }
  
      if (row && row.state === 'awaitingPIN') {
        const pin = ctx.message.text;
  
        // Retrieve the user's encrypted key and salt from the database
        db.get('SELECT encryptedKey, salt FROM users WHERE userid = ?', [userId], async (err, row) => {
          if (err) {
            console.error(err.message);
            ctx.reply('An error occurred.');
            return;
          }
  
          if (row) {
            try {
              const salt = Buffer.from(row.salt, 'hex'); // Convert the salt back to a Buffer
              const key = await getKeyFromPIN(pin, salt); // Generate the key using the retrieved salt
              const decryptedKey = decrypt(row.encryptedKey, key);
              // Send the decrypted key
              ctx.reply(`Your private key is: ${decryptedKey}`).then(sentMessage => {
                // Set a 30-second timeout to edit the message
                setTimeout(() => {
                    ctx.api.editMessageText(ctx.chat.id, sentMessage.message_id, "Your private key has been hidden for security.");
                }, 30000); // 30 seconds
              });      
      } catch (e) {
              console.error('Decryption failed:', e.message);
              ctx.reply('Failed to decrypt. Please check your PIN and try again.');
            }
          } else {
            ctx.reply("No wallet found for your user ID.");
          }
        });
  
        // Clear the user's state from the database after processing
        db.run('DELETE FROM user_states WHERE userid = ?', [userId]);
      } else if (row && row.state === 'awaitingDeleteConfirmation') {
        if (ctx.message.text === "yes delete my wallet") {
          db.run('DELETE FROM users WHERE userid = ?', [userId], () => {
            ctx.reply("Your wallet has been deleted.");
          });
        } else {
          ctx.reply("Wallet deletion cancelled.");
        }
        db.run('DELETE FROM user_states WHERE userid = ?', [userId]);
      }
    });
  });
  
// Start the bot
bot.start();
