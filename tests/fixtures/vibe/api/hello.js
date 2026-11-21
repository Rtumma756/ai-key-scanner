// Fixture API route: exported handler, no sign-in check anywhere.
export default async function handler(req, res) {
  const users = await db.collection("users").find().toArray();
  res.status(200).json(users);
}
