// { dg-do assemble  }
// GROUPS passed templates

        template<class K, class V> class MapLS { };
        class String {};
        class X1 { };
        class RefProto { };
        template<class REP> class Ref { };

        template <>        
        class MapLS<String, Ref<X1> >: public MapLS<String, RefProto> {
        public:
            ~MapLS();
        };
        
        MapLS<String, Ref<X1> >::~MapLS() { }

