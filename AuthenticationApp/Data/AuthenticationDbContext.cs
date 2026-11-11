using AuthenticationApp.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationApp.Data;

public class AuthenticationDbContext : DbContext
{
    public AuthenticationDbContext(DbContextOptions<AuthenticationDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("Users");

            entity.HasKey(u => u.UserID);

            entity.Property(u => u.UserID)
                .HasColumnName("UserID")
                .ValueGeneratedOnAdd();

            entity.Property(u => u.FullName)
                .HasColumnName("FullName")
                .HasMaxLength(100)
                .IsRequired();

            entity.Property(u => u.Email)
                .HasColumnName("Email")
                .HasMaxLength(255)
                .IsRequired();
            entity.Property(u => u.PasswordHash)
                .HasColumnName("PasswordHash")
                .HasMaxLength(500)
                .IsRequired();

            entity.Property(u => u.CreatedAt)
                .HasColumnName("CreatedAt");

            entity.HasIndex(u => u.Email)
                .IsUnique();

        });
}

}
