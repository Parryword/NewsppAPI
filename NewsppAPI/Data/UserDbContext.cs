using Microsoft.EntityFrameworkCore;
using NewsppAPI.Entities;

namespace NewsppAPI.Data;

public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
{
    public DbSet<User> Users { get; set; }
}