      ! { dg-do compile }
      ! { dg-options "-ffixed-form" }
      module foo
      end module foo

      subroutine bar1
      usefoo
      end
