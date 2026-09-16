'use strict';

// Prints a bcrypt hash to paste into LOGIN_PASSWORD_HASH.
//   npm run hash-password -- "your new password"
//   echo "your new password" | npm run hash-password

const bcrypt = require('bcryptjs');

async function readPassword() {
  if (process.argv[2]) return process.argv[2];
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  return input.replace(/\r?\n$/, '');
}

readPassword().then((password) => {
  if (password.length < 10) {
    console.error('Use a password of at least 10 characters.');
    process.exit(1);
  }
  console.log(bcrypt.hashSync(password, 12));
});
