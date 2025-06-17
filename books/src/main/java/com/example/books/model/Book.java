package com.example.books.model;

//import lombok.AllArgsConstructor;
//import lombok.Data;
//import lombok.NoArgsConstructor;

//issue with lombok annotations not working
public class Book {
    public Book(String bookId, String isbn, String title, String publisher, String datePublished) {
        this.bookId = bookId;
        this.isbn = isbn;
        this.title = title;
        this.publisher = publisher;
        this.datePublished = datePublished;
    }

    private String bookId;

    public Book() {
    }

    private String isbn;

    public String getBookId() {
        return bookId;
    }

    public void setBookId(String bookId) {
        this.bookId = bookId;
    }

    public String getIsbn() {
        return isbn;
    }

    public void setIsbn(String isbn) {
        this.isbn = isbn;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getPublisher() {
        return publisher;
    }

    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    public String getDatePublished() {
        return datePublished;
    }

    public void setDatePublished(String datePublished) {
        this.datePublished = datePublished;
    }

    private String title;
    private String publisher;
    private String datePublished;

}
