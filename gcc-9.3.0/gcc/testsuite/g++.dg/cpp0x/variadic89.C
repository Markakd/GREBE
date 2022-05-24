// { dg-do compile { target c++11 } }
// Contributed by Eric Niebler
template<typename T, typename U>
struct pair
{};

template<typename T>
struct test;

template<template<typename...> class T, typename... Args>
struct test<T<Args...> >
{};

test<pair<int, double> > t;
