export function excludePassword<User extends { password: string }>(
  user: User,
): Omit<User, 'password'> {
  const { password, ...userWithoutPassword } = user;
  return userWithoutPassword;
}