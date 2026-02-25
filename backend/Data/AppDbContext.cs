using Microsoft.EntityFrameworkCore;
using backend.Models;

namespace backend.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<User> Users => Set<User>();
    public DbSet<Car> Cars => Set<Car>();
    public DbSet<Tsb> Tsbs => Set<Tsb>();
    public DbSet<Obd> Obds => Set<Obd>();
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();

        modelBuilder.Entity<Car>()
            .HasIndex(c => new { c.Make, c.Model, c.Year })
            .IsUnique();

        modelBuilder.Entity<Tsb>()
            .HasOne(t => t.Car)
            .WithMany(c => c.Tsbs)
            .HasForeignKey(t => t.CarId)
            .IsRequired();
    }
}